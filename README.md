# Tunnelbees
Tunnelbees is a port knocking scheme that provides secure SSH access to a server using a zero knowledge-based protocol. This scheme is designed to be resistant to a powerful attacker that can observe and analyze packets, as well as scan ports. While public-key cryptography can be used for this case, tunnelbees allows even greater assurance, as the shared authentication secret between the client and the server is never sent over the wire.

Tunnelbees is inspired by the the Roman historian Appian. In his account of the Third Mithridatic War, he writes:
> With another army Lucullus besieged Themiscyra, which is named after one of the Amazons and is situated on the river Thermodon. The besiegers of this place brought up towers, built mounds, and dug tunnels so large that great subterranean battles could be fought in them. The inhabitants cut openings into these tunnels from above and thrust bears and other wild animals and swarms of bees into them against the workers. 

# How it works
- The client and the server have some shared secret `s`
- The server initializes all ports except 50 as an SSH honeypot
- The client sends an initialization message to the server on port `50` containing a random number `R`
- The server tests the client knows `s` using a ZK protocol
- The client and the server use a cryptographic function `f` to derive `N = f(s, R) mod 65535`
- The server accepts SSH requests on `N`, the client connects on port `N`
- Given `R` and `N`, the attacker cannot derive `s`.
