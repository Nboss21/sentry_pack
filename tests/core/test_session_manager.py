# from unittest.mock import Mock

# import pytest

# from core.session_manager import SessionManager
# from core.transport_base import ITransport
# from core.session_manager import AgentIdentity, SessionStatus


# def test_register_connected_session() -> None:
#     manager = SessionManager()

#     transport = Mock(spec=ITransport)
#     transport.is_alive.return_value = True

#     identity = AgentIdentity(
#         agent_id="agent-test-001",
#         name="Test Agent",
#     )

#     session = manager.register_connected_session(
#         identity=identity,
#         transport=transport,
#     )

#     assert session is not None
#     assert session.session_key == "agent-test-001"
#     assert session.identity is identity
#     assert session.transport is transport
#     assert session.status == SessionStatus.ACTIVE

#     assert (
#         manager.sessions["agent-test-001"]
#         is session
#     )

#     # The listener gave us an already-connected transport,
#     # so SessionManager must NOT connect it again.
#     transport.connect.assert_not_called()

# def test_register_connected_session_requires_live_transport() -> None:
#     manager = SessionManager()

#     transport = Mock(spec=ITransport)
#     transport.is_alive.return_value = False

#     identity = AgentIdentity(
#         agent_id="agent-test-002",
#         name="Test Agent",
#     )

#     with pytest.raises(RuntimeError):
#         manager.register_connected_session(
#             identity=identity,
#             transport=transport,
#         )

#     transport.connect.assert_not_called()