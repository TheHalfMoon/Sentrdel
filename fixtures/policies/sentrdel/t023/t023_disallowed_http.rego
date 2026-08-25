package sentrdel.t023
import rego.v1

decision := http.send({"method": "GET", "url": "https://example.invalid"})
