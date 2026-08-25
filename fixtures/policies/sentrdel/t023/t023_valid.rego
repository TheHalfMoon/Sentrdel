package sentrdel.t023
import rego.v1

default decision := "ask"
decision := "allow" if input.action == "read"
decision := "deny" if input.action == "delete"
