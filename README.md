# Tunnelbees
Tunnelbees is a SSH honeypot that can securely let a client through given a shared secret. By default, the Tunnelbees server will open ports 1 through 4096 to a SSH honeypot. Through a zero-knowledge handshake, a client and the Tunnelbees server can agree on a temporary, random port to open to proper SSH. This scheme is designed to be resistant to a powerful attacker that can observe, analyze, and replay packets, as well as scan ports. 

Tunnelbees uses Schnorr signatures for the interactive zero-knowledge scheme. Likewise, Tunnelbees relies on the discrete logarithm problem, so Shor's algorithm can efficiently crack this. When quantum supremacy? 
 
Tunnelbees is inspired by the the Roman historian Appian. In his account of the Third Mithridatic War, he writes:
> With another army Lucullus besieged Themiscyra, which is named after one of the Amazons and is situated on the river Thermodon. The besiegers of this place brought up towers, built mounds, and dug tunnels so large that great subterranean battles could be fought in them. The inhabitants cut openings into these tunnels from above and thrust bears and other wild animals and swarms of bees into them against the workers. 

# How it works (high-level)
- The client and the server have some shared secret `s`
- The server initializes all ports except 50 as an SSH honeypot
- The client sends an initialization message to the server on port `50` containing a random number `R`
- The server tests the client knows `s` using Schnorr
- The client and the server use a cryptographic function `f` to derive `N = f(s, R) mod 65535`
- The server accepts SSH requests on `N`, the client connects on port `N`
- Given `R` and `N`, the attacker cannot derive `s`.
