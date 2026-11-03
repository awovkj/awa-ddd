"""AWA-DDD 2.0 domain entities."""
from .campaign import new_campaign, public_view as campaign_view
from .coverage_claim import DIMENSIONS, make_claim
from .finding import new_finding, summary as finding_summary
from .gap import new_gap
from .hypothesis import FAMILIES, new_hypothesis, public_view as hypothesis_view
from .known_case import TRACKS, new_known_case, public_view as known_case_view
from .review import new_review_contract, validate_cross_role
from .test_recipe import new_recipe, public_view as recipe_view
from .test_run import new_run
from .universe import new_universe, summary as universe_summary

__all__ = [
    "DIMENSIONS", "FAMILIES", "TRACKS", "campaign_view", "finding_summary",
    "hypothesis_view", "known_case_view", "make_claim", "new_campaign", "new_finding",
    "new_gap", "new_hypothesis", "new_known_case", "new_recipe", "new_review_contract",
    "new_run", "new_universe", "recipe_view", "universe_summary", "validate_cross_role",
]
