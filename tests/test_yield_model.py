from __future__ import annotations

import pytest

from recon.intelligence.wordlists import CorpusCategory
from recon.intelligence.yield_model import (
    InMemoryYieldStore,
    TokenYieldCredit,
    YieldExecutionOutcome,
    YieldModel,
    YieldObservation,
    YieldQuery,
)


@pytest.mark.asyncio
async def test_task_success_is_separate_from_discovery_yield():
    store = InMemoryYieldStore()
    await store.append(
        YieldObservation(
            worker="http",
            action="probe",
            target_key="example.com",
            execution_outcome=YieldExecutionOutcome.SUCCEEDED,
            attempted_units=10,
            successful_hits=0,
            new_assets=0,
        )
    )
    estimate = await YieldModel(store).estimate(
        YieldQuery(target_key="example.com", worker="http", action="probe")
    )
    assert estimate.aggregate.execution_success_rate == 1.0
    assert estimate.aggregate.raw_hit_rate == 0.0


@pytest.mark.asyncio
async def test_token_query_uses_exact_token_credit_not_whole_batch():
    store = InMemoryYieldStore()
    await store.append(
        YieldObservation(
            worker="permutations",
            action="generate_targeted",
            target_key="example.com",
            attempted_units=10,
            successful_hits=1,
            new_assets=1,
            token_credits=(
                TokenYieldCredit(
                    token="warehouse",
                    category=CorpusCategory.DNS,
                    attempted_hypotheses=2,
                    successful_hits=1,
                    new_assets=1,
                ),
            ),
        )
    )
    estimate = await YieldModel(store).estimate_for_token(
        target_key="example.com",
        token="warehouse",
        category=CorpusCategory.DNS,
    )
    assert estimate.aggregate.attempted_units == 2
    assert estimate.aggregate.successful_hits == 1


@pytest.mark.asyncio
async def test_sparse_context_retains_information_gain():
    estimate = await YieldModel(InMemoryYieldStore()).estimate(
        YieldQuery(target_key="example.com", worker="new-worker")
    )
    assert estimate.uncertainty > 0.9
