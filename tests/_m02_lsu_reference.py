"""Frozen M02 pre-change production methods (from D02 local_lsa.py)."""


import struct


class OriginalLocalLSA:

    def build_update_body(self):
        if not self.entries:
            return None

        lsas = [
            entry["raw_lsa"]
            for _, entry in sorted(
                self.entries.items(),
                key=lambda item: item[0]
            )
        ]

        return (
            struct.pack("!I", len(lsas))
            + b"".join(lsas)
        )


    def build_pending_body(self, pending):
        if not pending:
            return None

        lsas = []

        for key in sorted(pending):
            local_lsa = self.entries.get(key)
            pending_lsa = pending[key]

            if local_lsa is None:
                continue

            same_instance = (
                local_lsa["ls_sequence"]
                == pending_lsa["ls_sequence"]
                and local_lsa["ls_checksum"]
                == pending_lsa["ls_checksum"]
            )

            if same_instance:
                lsas.append(
                    local_lsa["raw_lsa"]
                )

        if not lsas:
            return None

        body = (
            struct.pack("!I", len(lsas))
            + b"".join(lsas)
        )

        return body, len(lsas)

