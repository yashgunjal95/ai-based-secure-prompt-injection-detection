# ============================================================
# core/detection/ml_classifier.py
#
# Layer 2 — ML-Based Prompt Injection Classifier
#
# Responsibilities:
#   - Fine-tune a DistilBERT classifier on labeled prompt data
#   - Run inference and return an injection probability score (0.0–1.0)
#   - Fall back to a TF-IDF + Logistic Regression model if
#     transformers / torch are unavailable (CPU-constrained environments)
#   - Save / load weights for persistence across restarts
#
# Two modes:
#   TRANSFORMER  — DistilBERT fine-tuned (preferred, GPU/CPU)
#   LIGHTWEIGHT  — TF-IDF + LogisticRegression (fallback, always works)
# ============================================================

from __future__ import annotations

import json
import os
import pickle
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# ── Optional heavy imports ───────────────────────────────────────────────────
# We guard these so the rest of the codebase can still import this module
# even on a minimal environment.
try:
    import torch
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )
    from torch.utils.data import Dataset as TorchDataset
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


# ── Project imports ──────────────────────────────────────────────────────────
import sys
_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
try:
    from config import settings
except Exception:
    from secure_agent.config import settings  # fallback for offline envs


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

class ClassifierMode(str, Enum):
    TRANSFORMER = "transformer"
    LIGHTWEIGHT = "lightweight"
    UNTRAINED   = "untrained"


@dataclass
class MLClassifierResult:
    """Output of a single ML classifier inference call."""
    prompt:           str
    risk_score:       float        # 0.0 (safe) – 1.0 (injection)
    predicted_label:  str          # "safe" or "injection"
    confidence:       float        # model confidence in its prediction
    model_mode:       ClassifierMode
    inference_time_ms: float

    @property
    def summary(self) -> str:
        return (
            f"ML [{self.model_mode.value}] | "
            f"label={self.predicted_label} | "
            f"score={self.risk_score:.4f} | "
            f"confidence={self.confidence:.4f} | "
            f"time={self.inference_time_ms:.2f}ms"
        )


# ---------------------------------------------------------------------------
# PyTorch Dataset Wrapper (used during fine-tuning only)
# ---------------------------------------------------------------------------

if _TORCH_AVAILABLE:
    class _PromptDataset(TorchDataset):
        def __init__(
            self,
            texts:     list[str],
            labels:    list[int],
            tokenizer,
            max_length: int = 256,
        ) -> None:
            self.encodings = tokenizer(
                texts,
                truncation=True,
                padding=True,
                max_length=max_length,
                return_tensors="pt",
            )
            self.labels = torch.tensor(labels, dtype=torch.long)

        def __len__(self) -> int:
            return len(self.labels)

        def __getitem__(self, idx: int) -> dict:
            item = {k: v[idx] for k, v in self.encodings.items()}
            item["labels"] = self.labels[idx]
            return item


# ---------------------------------------------------------------------------
# Main Classifier
# ---------------------------------------------------------------------------

class MLPromptClassifier:
    """
    Layer 2 of the Prompt Firewall — ML-based injection classifier.

    Usage:
        clf = MLPromptClassifier()
        clf.train()                      # fine-tune on built-in dataset
        result = clf.predict(prompt)     # run inference

    The classifier auto-selects mode:
      1. TRANSFORMER  if torch + transformers are installed
      2. LIGHTWEIGHT  if only scikit-learn is available
      3. UNTRAINED    returns a neutral 0.5 score with a warning
    """

    # Paths
    _TRANSFORMER_DIR  = settings.ml_classifier.classifier_path
    _LIGHTWEIGHT_PATH = settings.ml_classifier.classifier_path.parent / "lightweight_clf.pkl"

    def __init__(self) -> None:
        self._mode: ClassifierMode = ClassifierMode.UNTRAINED
        self._tokenizer = None
        self._transformer_model = None
        self._lightweight_pipeline: Pipeline | None = None

        # Try to load an already-trained model
        self._auto_load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train(self, force_lightweight: bool = False) -> dict:
        """
        Fine-tune the classifier on the built-in labeled dataset.

        Args:
            force_lightweight: Skip transformer training and use
                               TF-IDF + LogReg (faster, lower accuracy).

        Returns:
            dict with training metrics and model mode used.
        """
        # Import dataset here to avoid circular issues at module load
        from models.classifier.training_data import get_texts_and_labels, dataset_stats

        texts, labels = get_texts_and_labels()
        stats = dataset_stats()
        print(f"\n[MLClassifier] Training on {stats}")

        if _TORCH_AVAILABLE and not force_lightweight:
            return self._train_transformer(texts, labels)
        elif _SKLEARN_AVAILABLE:
            return self._train_lightweight(texts, labels)
        else:
            raise RuntimeError(
                "Neither torch+transformers nor scikit-learn is installed. "
                "Cannot train the ML classifier."
            )

    def predict(self, prompt: str) -> MLClassifierResult:
        """
        Run inference on a single prompt.

        Returns:
            MLClassifierResult with risk_score and metadata.
        """
        if not prompt or not prompt.strip():
            return self._make_result(prompt, 0.0, "safe", 1.0)

        t_start = time.perf_counter()

        if self._mode == ClassifierMode.TRANSFORMER:
            score, confidence = self._predict_transformer(prompt)
        elif self._mode == ClassifierMode.LIGHTWEIGHT:
            score, confidence = self._predict_lightweight(prompt)
        else:
            # Untrained — return neutral score
            score, confidence = 0.5, 0.0

        elapsed_ms = (time.perf_counter() - t_start) * 1000
        label = "injection" if score >= 0.5 else "safe"

        return MLClassifierResult(
            prompt=prompt,
            risk_score=round(score, 4),
            predicted_label=label,
            confidence=round(confidence, 4),
            model_mode=self._mode,
            inference_time_ms=round(elapsed_ms, 3),
        )

    @property
    def mode(self) -> ClassifierMode:
        return self._mode

    @property
    def is_trained(self) -> bool:
        return self._mode != ClassifierMode.UNTRAINED

    # ------------------------------------------------------------------
    # Transformer Training & Inference
    # ------------------------------------------------------------------

    def _train_transformer(self, texts: list[str], labels: list[int]) -> dict:
        """Fine-tune DistilBERT on the labeled prompt dataset."""
        base_model = settings.ml_classifier.base_model
        save_dir   = self._TRANSFORMER_DIR
        save_dir.mkdir(parents=True, exist_ok=True)

        print(f"[MLClassifier] Loading base model: {base_model}")
        tokenizer = AutoTokenizer.from_pretrained(base_model)
        model     = AutoModelForSequenceClassification.from_pretrained(
            base_model,
            num_labels=2,
            id2label={0: "safe", 1: "injection"},
            label2id={"safe": 0, "injection": 1},
        )

        # Split: 80% train, 20% eval
        from sklearn.model_selection import train_test_split
        train_texts, eval_texts, train_labels, eval_labels = train_test_split(
            texts, labels, test_size=0.20, random_state=42, stratify=labels
        )

        train_dataset = _PromptDataset(train_texts, train_labels, tokenizer)
        eval_dataset  = _PromptDataset(eval_texts,  eval_labels,  tokenizer)

        training_args = TrainingArguments(
            output_dir=str(save_dir / "checkpoints"),
            num_train_epochs=5,
            per_device_train_batch_size=8,
            per_device_eval_batch_size=16,
            warmup_steps=10,
            weight_decay=0.01,
            logging_dir=str(save_dir / "logs"),
            logging_steps=10,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            report_to="none",           # disable wandb / mlflow
            no_cuda=not torch.cuda.is_available(),
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
        )

        print("[MLClassifier] Starting transformer fine-tuning...")
        train_result = trainer.train()

        # Persist
        model.save_pretrained(str(save_dir))
        tokenizer.save_pretrained(str(save_dir))

        # Save metadata
        meta = {
            "base_model":   base_model,
            "mode":         ClassifierMode.TRANSFORMER.value,
            "train_samples": len(train_texts),
            "eval_samples":  len(eval_texts),
            "train_loss":    round(train_result.training_loss, 4),
        }
        (save_dir / "meta.json").write_text(json.dumps(meta, indent=2))

        # Load into memory
        self._tokenizer         = tokenizer
        self._transformer_model = model
        self._mode              = ClassifierMode.TRANSFORMER

        print(f"[MLClassifier] Transformer saved to {save_dir}")
        return meta

    def _predict_transformer(self, prompt: str) -> tuple[float, float]:
        """Run a single inference pass through the fine-tuned transformer."""
        inputs = self._tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=settings.ml_classifier.max_token_length,
            padding=True,
        )

        self._transformer_model.eval()
        with torch.no_grad():
            logits = self._transformer_model(**inputs).logits

        probs      = torch.softmax(logits, dim=-1)[0]
        inject_prob = float(probs[1])   # index 1 = "injection"
        confidence  = float(probs.max())
        return inject_prob, confidence

    # ------------------------------------------------------------------
    # Lightweight (TF-IDF + LogReg) Training & Inference
    # ------------------------------------------------------------------

    def _train_lightweight(self, texts: list[str], labels: list[int]) -> dict:
        """Train a TF-IDF + Logistic Regression pipeline as fallback."""
        print("[MLClassifier] Training lightweight TF-IDF + LogReg pipeline...")

        from sklearn.model_selection import train_test_split
        train_texts, eval_texts, train_labels, eval_labels = train_test_split(
            texts, labels, test_size=0.20, random_state=42, stratify=labels
        )

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 3),
                max_features=8000,
                sublinear_tf=True,
                min_df=1,
            )),
            ("clf", LogisticRegression(
                C=1.0,
                max_iter=1000,
                class_weight="balanced",
                random_state=42,
            )),
        ])

        pipeline.fit(train_texts, train_labels)
        eval_preds = pipeline.predict(eval_texts)

        report = classification_report(
            eval_labels, eval_preds,
            target_names=["safe", "injection"],
            output_dict=True,
        )

        # Persist
        self._LIGHTWEIGHT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(self._LIGHTWEIGHT_PATH, "wb") as f:
            pickle.dump(pipeline, f)

        self._lightweight_pipeline = pipeline
        self._mode = ClassifierMode.LIGHTWEIGHT

        metrics = {
            "mode":      ClassifierMode.LIGHTWEIGHT.value,
            "accuracy":  round(report["accuracy"], 4),
            "precision": round(report["injection"]["precision"], 4),
            "recall":    round(report["injection"]["recall"], 4),
            "f1":        round(report["injection"]["f1-score"], 4),
        }
        print(f"[MLClassifier] Lightweight trained | metrics={metrics}")
        return metrics

    def _predict_lightweight(self, prompt: str) -> tuple[float, float]:
        """Run inference using the TF-IDF + LogReg pipeline."""
        proba      = self._lightweight_pipeline.predict_proba([prompt])[0]
        inject_prob = float(proba[1])    # index 1 = injection class
        confidence  = float(proba.max())
        return inject_prob, confidence

    # ------------------------------------------------------------------
    # Model Persistence
    # ------------------------------------------------------------------

    def _auto_load(self) -> None:
        """
        Auto-detect and load the best available trained model.
        Priority: TRANSFORMER > LIGHTWEIGHT > UNTRAINED
        """
        # Try transformer first
        if _TORCH_AVAILABLE and self._TRANSFORMER_DIR.exists():
            meta_path = self._TRANSFORMER_DIR / "meta.json"
            if meta_path.exists():
                try:
                    self._tokenizer = AutoTokenizer.from_pretrained(
                        str(self._TRANSFORMER_DIR)
                    )
                    self._transformer_model = (
                        AutoModelForSequenceClassification.from_pretrained(
                            str(self._TRANSFORMER_DIR)
                        )
                    )
                    self._mode = ClassifierMode.TRANSFORMER
                    print(f"[MLClassifier] Loaded transformer from {self._TRANSFORMER_DIR}")
                    return
                except Exception as e:
                    print(f"[MLClassifier] Warning: Could not load transformer: {e}")

        # Try lightweight fallback
        if _SKLEARN_AVAILABLE and self._LIGHTWEIGHT_PATH.exists():
            try:
                with open(self._LIGHTWEIGHT_PATH, "rb") as f:
                    self._lightweight_pipeline = pickle.load(f)
                self._mode = ClassifierMode.LIGHTWEIGHT
                print(f"[MLClassifier] Loaded lightweight model from {self._LIGHTWEIGHT_PATH}")
                return
            except Exception as e:
                print(f"[MLClassifier] Warning: Could not load lightweight model: {e}")

        print(
            "[MLClassifier] No trained model found. "
            "Call .train() before using .predict(). "
            "Returning neutral scores until then."
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_result(
        self,
        prompt: str,
        score: float,
        label: str,
        confidence: float,
        elapsed_ms: float = 0.0,
    ) -> MLClassifierResult:
        return MLClassifierResult(
            prompt=prompt,
            risk_score=score,
            predicted_label=label,
            confidence=confidence,
            model_mode=self._mode,
            inference_time_ms=elapsed_ms,
        )