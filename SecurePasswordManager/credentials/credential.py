from dataclasses import dataclass


@dataclass
class Credential:
    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""