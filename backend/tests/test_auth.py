import unittest
from types import SimpleNamespace

from fastapi import HTTPException
from pydantic import ValidationError

from app.api.auth_routes import _validate_user_deletion
from app.schemas.auth import CreateUserRequest, Credentials
from app.services.auth import hash_password, session_token_hash, verify_password


class AuthTests(unittest.TestCase):
    def test_passwords_use_salted_hashes_and_verify(self) -> None:
        first = hash_password("A sufficiently long password")
        second = hash_password("A sufficiently long password")

        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("A sufficiently long password", first)[0])
        self.assertFalse(verify_password("wrong password", first)[0])

    def test_username_is_normalized(self) -> None:
        payload = Credentials(username="  SOC.Admin  ", password="ThreatLens!Secure")

        self.assertEqual(payload.username, "soc.admin")

    def test_password_policy_is_enforced(self) -> None:
        invalid_passwords = [
            "Short!Password",
            "lowercase!password",
            "UPPERCASE!PASSWORD",
            "NoSpecialPassword",
        ]

        for password in invalid_passwords:
            with self.subTest(password=password), self.assertRaises(ValidationError):
                Credentials(username="analyst", password=password)

    def test_role_is_restricted(self) -> None:
        with self.assertRaises(ValidationError):
            CreateUserRequest(
                username="analyst",
                password="ThreatLens!Secure",
                role="owner",
            )

    def test_session_token_hash_is_stable_without_storing_token(self) -> None:
        digest = session_token_hash("raw-secret-token")

        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, "raw-secret-token")

    def test_user_cannot_delete_own_account(self) -> None:
        target = SimpleNamespace(id=7, role="admin")

        with self.assertRaises(HTTPException) as error:
            _validate_user_deletion(actor_id=7, target=target, admin_count=2)

        self.assertEqual(error.exception.status_code, 400)

    def test_last_admin_cannot_be_deleted(self) -> None:
        target = SimpleNamespace(id=8, role="admin")

        with self.assertRaises(HTTPException) as error:
            _validate_user_deletion(actor_id=7, target=target, admin_count=1)

        self.assertEqual(error.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
