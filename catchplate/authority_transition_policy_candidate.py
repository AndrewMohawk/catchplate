"""Finite generation intake kernels. Canary evidence/Setup are separate work."""
from types import MappingProxyType
from catchplate import authority_policy_candidate as profile
from catchplate.authority_transition_policy_candidate_claim import GenerationClaimKernel
from catchplate.authority_transition_policy_candidate_publication import GenerationPublicationKernel

KERNELS = MappingProxyType({profile.OP_CLAIM: GenerationClaimKernel(), profile.OP_PUBLISH: GenerationPublicationKernel()})
