"""Separately registered policy-publisher purpose; no token-profile alias."""
from types import MappingProxyType
from catchplate import authority_policy_file_approval as profile
from catchplate.authority_transition_publication_approval import PublicationApprovalKernel

KERNELS = MappingProxyType({operation: PublicationApprovalKernel(operation) for operation in profile.OPERATIONS})
