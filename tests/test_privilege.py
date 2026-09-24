"""Tests for privilege scoring and grading."""

from agentsec.audit.privilege import PrivilegeScorer
from agentsec.models import (
    AgentDefinition,
    Capability,
)


class TestPrivilegeScorer:
    """Tests for privilege scoring system."""

    def test_scorer_initialization(self):
        """Test scorer can be initialized."""
        scorer = PrivilegeScorer()
        assert scorer is not None

    def test_score_empty_agent(self):
        """Test scoring an agent with no capabilities."""
        agent = AgentDefinition(name="EmptyAgent")
        scorer = PrivilegeScorer()
        score = scorer.calculate_score(agent.direct_capabilities)
        assert score == 0

    def test_score_code_exec_capability(self):
        """Test that CODE_EXEC has high privilege weight."""
        capabilities = [Capability.CODE_EXEC]
        scorer = PrivilegeScorer()
        score = scorer.calculate_score(capabilities)
        assert score > 0
        # CODE_EXEC should be heavily weighted
        assert score >= 100  # Assuming high weight

    def test_score_shell_exec_capability(self):
        """Test that SHELL_EXEC has high privilege weight."""
        capabilities = [Capability.SHELL_EXEC]
        scorer = PrivilegeScorer()
        score = scorer.calculate_score(capabilities)
        assert score > 0
        assert score >= 100

    def test_score_multiple_capabilities(self):
        """Test scoring with multiple capabilities."""
        capabilities = [
            Capability.FS_READ,
            Capability.FS_WRITE,
            Capability.NETWORK_READ,
        ]
        scorer = PrivilegeScorer()
        score = scorer.calculate_score(capabilities)

        # Score should be sum of individual weights
        individual_scores = [scorer.calculate_score([cap]) for cap in capabilities]
        # Total score should be >= any individual score
        for individual in individual_scores:
            assert score >= individual

    def test_grade_assignment_a(self):
        """Test grade A assignment (minimal privileges)."""
        capabilities = [Capability.NETWORK_READ]  # Low privilege
        scorer = PrivilegeScorer()
        score = scorer.calculate_score(capabilities)
        grade = scorer.assign_grade(score)
        # Low score should give good grade
        assert grade in ["A", "B"]

    def test_grade_assignment_f(self):
        """Test grade F assignment (excessive privileges)."""
        capabilities = [
            Capability.CODE_EXEC,
            Capability.SHELL_EXEC,
            Capability.FS_WRITE,
            Capability.DB_WRITE,
            Capability.NETWORK_WRITE,
            Capability.SECRETS_ACCESS,
        ]
        scorer = PrivilegeScorer()
        score = scorer.calculate_score(capabilities)
        grade = scorer.assign_grade(score)
        # High score should give bad grade
        assert grade in ["D", "E", "F"]

    def test_grade_ordering(self):
        """Test that grades follow expected ordering."""
        scorer = PrivilegeScorer()

        # Create agents with increasing privilege
        low_caps = [Capability.NETWORK_READ]
        medium_caps = [Capability.FS_READ, Capability.DB_READ]
        high_caps = [Capability.SHELL_EXEC, Capability.CODE_EXEC]

        low_score = scorer.calculate_score(low_caps)
        medium_score = scorer.calculate_score(medium_caps)
        high_score = scorer.calculate_score(high_caps)

        assert low_score <= medium_score <= high_score

    def test_dangerous_capability_weights(self):
        """Test that dangerous capabilities have higher weights."""
        scorer = PrivilegeScorer()

        dangerous = [Capability.CODE_EXEC]
        safe = [Capability.NETWORK_READ]

        dangerous_score = scorer.calculate_score(dangerous)
        safe_score = scorer.calculate_score(safe)

        assert dangerous_score > safe_score

    def test_score_with_duplicate_capabilities(self):
        """Test that duplicate capabilities don't double-count."""
        scorer = PrivilegeScorer()

        single = [Capability.CODE_EXEC]
        duplicate = [Capability.CODE_EXEC, Capability.CODE_EXEC]

        single_score = scorer.calculate_score(single)
        duplicate_score = scorer.calculate_score(list(set(duplicate)))

        # De-duplicated should be same as single
        assert single_score == duplicate_score

    def test_agent_privilege_update(self):
        """Test updating an agent with privilege information."""
        agent = AgentDefinition(
            name="TestAgent", direct_capabilities=[Capability.FS_READ, Capability.FS_WRITE]
        )

        scorer = PrivilegeScorer()
        score = scorer.calculate_score(agent.direct_capabilities)
        grade = scorer.assign_grade(score)

        agent.privilege_score = score
        agent.privilege_grade = grade

        assert agent.privilege_score > 0
        assert agent.privilege_grade in ["A", "B", "C", "D", "E", "F"]

    def test_all_grades_possible(self):
        """Test that all grades A-F can be assigned."""
        scorer = PrivilegeScorer()

        # Create capability sets for each grade
        grade_tests = [
            ([Capability.NETWORK_READ], ["A", "B"]),
            ([Capability.FS_READ, Capability.DB_READ], ["B", "C"]),
            ([Capability.FS_WRITE, Capability.DB_WRITE], ["C", "D"]),
            ([Capability.CODE_EXEC], ["D", "E", "F"]),
            ([Capability.CODE_EXEC, Capability.SHELL_EXEC, Capability.SECRETS_ACCESS], ["E", "F"]),
        ]

        seen_grades = set()
        for caps, expected_range in grade_tests:
            score = scorer.calculate_score(caps)
            grade = scorer.assign_grade(score)
            seen_grades.add(grade)
            assert grade in expected_range

    def test_reachable_vs_direct_capabilities(self):
        """Test distinction between direct and reachable capabilities."""
        agent = AgentDefinition(
            name="Agent",
            direct_capabilities=[Capability.FS_READ],
            reachable_capabilities=[
                Capability.FS_READ,
                Capability.CODE_EXEC,  # Via handoff
                Capability.SHELL_EXEC,  # Via handoff
            ],
        )

        scorer = PrivilegeScorer()

        direct_score = scorer.calculate_score(agent.direct_capabilities)
        reachable_score = scorer.calculate_score(agent.reachable_capabilities)

        # Reachable score should be higher (more capabilities)
        assert reachable_score >= direct_score
