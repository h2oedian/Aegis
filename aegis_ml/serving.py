import logging
from functools import lru_cache

import joblib
from django.conf import settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_anomaly_model():
    """Load the trained AnomalyModel from disk, cached for the process's life.

    Returns None instead of raising when no model has been trained yet, so
    a server that hasn't run `train_anomaly_models` still serves requests --
    just with the model's contribution to the risk score fixed at 0.
    """
    try:
        return joblib.load(settings.AEGIS_ANOMALY_MODEL_PATH)
    except (OSError, EOFError) as exc:
        logger.warning(
            "No anomaly model at %s, scoring with rules only: %s",
            settings.AEGIS_ANOMALY_MODEL_PATH,
            exc,
        )
        return None


def model_score(features: dict[str, float]) -> float:
    model = get_anomaly_model()
    return model.score(features) if model is not None else 0.0
