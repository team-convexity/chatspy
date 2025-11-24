import uuid
import base64
import struct
import hashlib


class ChatsRecord:
    @staticmethod
    def resolve_id(obj, deterministic=False):
        """
        Convert django decimal IDs into base64 gUID string and return it.
        """
        if isinstance(obj, dict):
            return ChatsRecord.to_global_id(type(obj).__name__, int(obj.get("id")))

        if isinstance(obj.id, str):
            return obj.id

        return ChatsRecord.to_global_id(type(obj).__name__, int(obj.id), deterministic)

    @staticmethod
    def to_global_id(type_name, id, deterministic=False):
        """
        args:
            type_name (str): The type of the object
            django_id (int): The Django-style numeric ID

        returns:
            str: Base64 encoded GUID
        """

        assert isinstance(id, int), "id should be of int type"

        # encode negative numbers by setting the MSB and storing the absolute value
        if id < 0:
            encoded_id = (1 << 63) | (-id)  # set msb to 1 and store absolute value
        else:
            encoded_id = id  # Positive numbers remain unchanged

        if deterministic:
            hash_input = f"{type_name}:{encoded_id}".encode("utf-8")
            unique_part = hashlib.sha256(hash_input).digest()[:8]

        else:
            unique_part = uuid.uuid4().bytes[:8]

        # embed the numeric ID into a GUID
        # convert django_id into a 64-bit binary representation
        id_bytes = struct.pack(">Q", encoded_id)
        # combine unique_part and id_bytes
        guid_bytes = unique_part + id_bytes

        # combine type name with GUID bytes
        combined = f"{type_name}:".encode("utf-8") + guid_bytes
        # encode in Base64
        return base64.urlsafe_b64encode(combined).decode("ascii").rstrip("=")

    @staticmethod
    def from_global_id(encoded_str):
        """
        args:
            encoded_str (str): Base64 encoded GUID

        returns:
            tuple: (type_name, django_id)
        """
        # handle common invalid values from frontend
        if not encoded_str or encoded_str in ("undefined", "null", "None"):
            raise ValueError(f"Invalid ID: '{encoded_str}' is not a valid encoded ID")

        # add padding for base64 decoding
        padded_str = encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4)

        # decode base64
        decoded = base64.urlsafe_b64decode(padded_str)

        # split into type name and GUID bytes
        type_name, guid_bytes = decoded.split(b":", 1)

        # extract the numeric ID (last 8 bytes of the GUID)
        encoded_id = struct.unpack(">Q", guid_bytes[-8:])[0]
        # decode negative numbers by checking the MSB
        if encoded_id & (1 << 63):  # check if the MSB is set
            django_id = -(encoded_id & ~(1 << 63))  # clear the MSB and negate the value
        else:
            django_id = encoded_id

        return type_name.decode("utf-8"), django_id
