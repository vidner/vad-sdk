import datetime
import json
import unittest

from vad_checker.protocol import Context, Outcome, Result, State, decode_job, encode_result


class ProtocolTest(unittest.TestCase):
    def test_get_context_is_per_flag(self) -> None:
        deadline = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=10)
        context = decode_job(json.dumps({
            "version": 1,
            "id": "job-1",
            "attempt": 1,
            "operation": "GET",
            "deadline": deadline.isoformat(),
            "game": {"id": 1, "tick": 7},
            "service": {"id": 2, "key": "notes"},
            "team": {"id": 3, "name": "team-03", "host": "10.80.0.3"},
            "store": {"id": 4, "key": "private_notes"},
            "flag": "CTF{example}",
            "public": {"note_id": "8"},
            "private": {"password": "secret"},
        }).encode())
        self.assertEqual(context.public, {"note_id": "8"})
        self.assertEqual(context.private, {"password": "secret"})
        self.assertEqual(context.idempotency_key, "job-1")

    def test_successful_put_requires_both_state_objects(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        context = Context("job", 1, "PUT", now, 1, 1, "notes", "team", "10.80.0.1", "store", "flag", None, None)
        payload = encode_result(
            context,
            Result(Outcome.SUCCESS, state=State({"id": "1"}, {"password": "x"})),
            now,
            now,
        )
        decoded = json.loads(payload)
        self.assertEqual(decoded["public"], {"id": "1"})
        self.assertEqual(decoded["private"], {"password": "x"})

    def test_successful_put_rejects_non_object_state(self) -> None:
        now = datetime.datetime.now(datetime.UTC)
        context = Context("job", 1, "PUT", now, 1, 1, "notes", "team", "10.80.0.1", "store", "flag", None, None)
        with self.assertRaisesRegex(ValueError, "public state must be an object"):
            encode_result(
                context,
                Result(Outcome.SUCCESS, state=State([], {})),
                now,
                now,
            )


if __name__ == "__main__":
    unittest.main()
