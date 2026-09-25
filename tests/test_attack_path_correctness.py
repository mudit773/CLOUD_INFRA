import unittest
import networkx as nx

from app.attack.crown_jewels import find_crown_jewels
from app.attack.attack_paths import find_attack_paths
from app.attack.choke_points import find_choke_points
from app.graph.nodes import GraphNode


class TestCrownJewelClassification(unittest.TestCase):

    def _create_node(self, graph, node_id, node_type, attributes=None, tags=None, security=None):
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            attributes=attributes or {},
            tags=tags or {},
            security_config=security or {},
        )
        graph.add_node(node_id, data=node)

    def test_01_ordinary_instance_not_crown_jewel(self):
        """1. Ordinary EC2/VM instance is NOT a crown jewel solely because it is exposed."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_instance.bastion", "aws_instance", security={"internet_exposed": True})
        self._create_node(graph, "azurerm_linux_virtual_machine.web", "azurerm_linux_virtual_machine", security={"public_ip": True})
        self._create_node(graph, "google_compute_instance.app", "google_compute_instance", attributes={"publicly_accessible": True})

        jewels = find_crown_jewels(graph)
        self.assertNotIn("aws_instance.bastion", jewels)
        self.assertNotIn("azurerm_linux_virtual_machine.web", jewels)
        self.assertNotIn("google_compute_instance.app", jewels)

    def test_02_public_subnet_not_crown_jewel(self):
        """2. Public subnet is NOT a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_subnet.public-subnet", "aws_subnet", attributes={"map_public_ip_on_launch": True})
        jewels = find_crown_jewels(graph)
        self.assertNotIn("aws_subnet.public-subnet", jewels)

    def test_03_security_group_not_crown_jewel(self):
        """3. Security group is NOT a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_security_group.ssh_open", "aws_security_group")
        jewels = find_crown_jewels(graph)
        self.assertNotIn("aws_security_group.ssh_open", jewels)

    def test_04_load_balancer_not_crown_jewel(self):
        """4. Load balancer is NOT a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_lb.public_alb", "aws_lb", attributes={"scheme": "internet-facing"})
        jewels = find_crown_jewels(graph)
        self.assertNotIn("aws_lb.public_alb", jewels)

    def test_05_database_is_crown_jewel(self):
        """5. Database is a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_db_instance.main_db", "aws_db_instance")
        self._create_node(graph, "google_sql_database_instance.postgres", "google_sql_database_instance")
        self._create_node(graph, "azurerm_mssql_database.sql_db", "azurerm_mssql_database")

        jewels = find_crown_jewels(graph)
        self.assertIn("aws_db_instance.main_db", jewels)
        self.assertIn("google_sql_database_instance.postgres", jewels)
        self.assertIn("azurerm_mssql_database.sql_db", jewels)

    def test_06_secret_manager_is_crown_jewel(self):
        """6. Secret/key vault/secret manager is a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_secretsmanager_secret.api_key", "aws_secretsmanager_secret")
        self._create_node(graph, "azurerm_key_vault_secret.db_pass", "azurerm_key_vault_secret")

        jewels = find_crown_jewels(graph)
        self.assertIn("aws_secretsmanager_secret.api_key", jewels)
        self.assertIn("azurerm_key_vault_secret.db_pass", jewels)

    def test_07_kms_key_is_crown_jewel(self):
        """7. KMS/encryption key is a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_kms_key.master_key", "aws_kms_key")
        self._create_node(graph, "google_kms_crypto_key.gcp_key", "google_kms_crypto_key")

        jewels = find_crown_jewels(graph)
        self.assertIn("aws_kms_key.master_key", jewels)
        self.assertIn("google_kms_crypto_key.gcp_key", jewels)

    def test_08_sensitive_storage_is_crown_jewel(self):
        """8. Sensitive storage is a crown jewel."""
        graph = nx.DiGraph()
        self._create_node(graph, "aws_s3_bucket.user_data", "aws_s3_bucket")
        self._create_node(graph, "google_storage_bucket.analytics", "google_storage_bucket")

        jewels = find_crown_jewels(graph)
        self.assertIn("aws_s3_bucket.user_data", jewels)
        self.assertIn("google_storage_bucket.analytics", jewels)


class TestAttackPathTraversalCorrectness(unittest.TestCase):

    def _create_node(self, graph, node_id, node_type="custom_resource", attributes=None, security=None):
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            attributes=attributes or {},
            security_config=security or {},
        )
        graph.add_node(node_id, data=node)

    def test_01_controlled_fixture_web_to_database(self):
        """
        Controlled Fixture:
        Internet -> public security group -> web instance -> database
        Expected: Meaningful attack path ending at database.
        """
        graph = nx.DiGraph()
        self._create_node(graph, "internet", "external")
        self._create_node(graph, "aws_security_group.public_ingress", "aws_security_group")
        self._create_node(graph, "aws_instance.web_app", "aws_instance")
        self._create_node(graph, "aws_db_instance.customer_db", "aws_db_instance")

        graph.add_edge("internet", "aws_security_group.public_ingress", type="EXPOSED_TO")
        graph.add_edge("aws_instance.web_app", "aws_security_group.public_ingress", type="REFERENCES_RESOURCE")
        graph.add_edge("aws_instance.web_app", "aws_db_instance.customer_db", type="REFERENCES_RESOURCE")

        entry_points = ["aws_security_group.public_ingress"]
        crown_jewels = ["aws_db_instance.customer_db"]

        paths = find_attack_paths(graph, entry_points, crown_jewels)

        self.assertTrue(len(paths) > 0, "Expected valid attack path to database")
        for p in paths:
            self.assertEqual(p["target"], "aws_db_instance.customer_db")
            self.assertEqual(p["nodes"][-1], "aws_db_instance.customer_db")

    def test_02_internet_subnet_bastion_no_attack_path(self):
        """
        Controlled Fixture:
        Internet -> public subnet -> bastion (where bastion is an ordinary compute resource)
        No sensitive target / crown jewel.
        Expected: attack_paths == []
        """
        graph = nx.DiGraph()
        self._create_node(graph, "internet", "external")
        self._create_node(graph, "aws_subnet.public_subnet", "aws_subnet")
        self._create_node(graph, "aws_instance.bastion", "aws_instance")

        graph.add_edge("internet", "aws_subnet.public_subnet", type="EXPOSED_TO")
        graph.add_edge("aws_instance.bastion", "aws_subnet.public_subnet", type="DEPLOYED_IN")

        entry_points = ["aws_subnet.public_subnet"]
        crown_jewels = find_crown_jewels(graph)  # bastion is not a crown jewel

        paths = find_attack_paths(graph, entry_points, crown_jewels)
        self.assertEqual(paths, [], "Expected zero attack paths when no crown jewel exists in the graph")

    def test_03_no_topology_permutation_loops(self):
        """
        Ensure traversal does NOT generate arbitrary topology permutations such as
        internet -> subnet -> instance -> security_group -> subnet -> instance.
        """
        graph = nx.DiGraph()
        self._create_node(graph, "internet", "external")
        self._create_node(graph, "aws_subnet.public_subnet", "aws_subnet")
        self._create_node(graph, "aws_security_group.sg1", "aws_security_group")
        self._create_node(graph, "aws_instance.inst1", "aws_instance")
        self._create_node(graph, "aws_instance.inst2", "aws_instance")
        self._create_node(graph, "aws_db_instance.prod_db", "aws_db_instance")

        graph.add_edge("internet", "aws_subnet.public_subnet", type="EXPOSED_TO")
        graph.add_edge("aws_instance.inst1", "aws_subnet.public_subnet", type="DEPLOYED_IN")
        graph.add_edge("aws_instance.inst1", "aws_security_group.sg1", type="ATTACHED_TO")
        graph.add_edge("aws_instance.inst2", "aws_security_group.sg1", type="ATTACHED_TO")
        graph.add_edge("aws_instance.inst2", "aws_subnet.public_subnet", type="DEPLOYED_IN")
        graph.add_edge("aws_instance.inst1", "aws_db_instance.prod_db", type="REFERENCES_RESOURCE")

        entry_points = ["aws_subnet.public_subnet"]
        crown_jewels = ["aws_db_instance.prod_db"]

        paths = find_attack_paths(graph, entry_points, crown_jewels)

        # Every path must be short and direct, with no bouncing loops
        for p in paths:
            self.assertEqual(p["nodes"][-1], "aws_db_instance.prod_db")
            self.assertLessEqual(p["length"], 4, "Paths must be direct with no topology permutation loops")


if __name__ == "__main__":
    unittest.main()
