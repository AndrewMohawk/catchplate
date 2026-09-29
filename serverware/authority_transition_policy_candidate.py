"""Finite generation intake kernels. Canary evidence/Setup are separate work."""
from types import MappingProxyType
from serverware import authority_policy_candidate as profile
from serverware.authority_transition_policy_candidate_claim import GenerationClaimKernel
from serverware.authority_transition_policy_candidate_publication import GenerationPublicationKernel

KERNELS = MappingProxyType({profile.OP_CLAIM: GenerationClaimKernel(), profile.OP_PUBLISH: GenerationPublicationKernel()})
