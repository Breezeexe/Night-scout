from __future__ import annotations

from recon.core.events import Event, EventType
from recon.intelligence.vocabulary import VocabularyCategory, VocabularyProjector


def test_url_projection_keeps_query_names_not_values():
    projector = VocabularyProjector()
    event = Event(
        type=EventType.API_ENDPOINT,
        value="https://api.example.com/v2/orders?tenantId=TOPSECRET&debug=true",
        source="javascript:test",
        confidence=0.8,
    )

    observations = projector.project_event(event)
    tokens = {item.token for item in observations}
    assert "tenantId" in tokens
    assert "debug" in tokens
    assert "TOPSECRET" not in tokens
    assert "true" not in tokens

    parameter = next(item for item in observations if item.token == "tenantId")
    assert VocabularyCategory.PARAMETER in parameter.categories
    assert parameter.case_sensitive is True


def test_secret_tagged_event_never_enters_target_vocabulary():
    projector = VocabularyProjector()
    event = Event(
        type=EventType.ARTIFACT,
        value="ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        source="mobile:test",
        tags={"possible-secret"},
    )
    assert projector.project_event(event) == ()


def test_hostname_semantics_extract_environment_service_region():
    projector = VocabularyProjector()
    event = Event(
        type=EventType.DNS_NAME,
        value="warehouse-api-preprod-msk-01.example.com",
        source="dns:test",
        tags={"confirmed"},
        confidence=0.95,
    )
    observations = {item.token: item for item in projector.project_event(event)}
    assert VocabularyCategory.ENVIRONMENT in observations["preprod"].categories
    assert VocabularyCategory.SERVICE in observations["api"].categories
    assert VocabularyCategory.REGION in observations["msk"].categories
    assert "01" not in observations
