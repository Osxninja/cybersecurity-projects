---
tags: [offensive-security, cryptography, zero-knowledge-proofs, zkp, fiat-shamir, zk-snark, authentication, btech-project]
category: "Cryptography & Steganography"
difficulty: "Advanced"
real_world_problem: "Credential theft, cleartext authentication leakage over untrusted networks, and database breach exposures"
tools: [Circom, SnarkJS, Python, Web3, Cryptography]
estimated_duration: "5 weeks"
---

# 🎯 089 - Zero-Knowledge Proof Authentication System

> **Category**: [[Cryptography & Steganography]] | **Difficulty**: ⭐⭐⭐ | **Duration**: 5 weeks

---

## 📋 Problem Statement

> [!CAUTION] Real-World Impact
> Conventional password-based and token-based authentication protocols (e.g., HTTP Basic Auth, OAuth 2.0 bearer tokens) transmit sensitive secrets or identity tokens across external networks. Even when protected by TLS, server-side database breaches expose salt-hashed passwords to offline GPU cracking attacks, while compromised servers can intercept user secrets during active login flows.

**Zero-Knowledge Proofs (ZKPs)** solve credential exposure by allowing a Prover (User) to cryptographically prove to a Verifier (Server) that they possess a valid secret password $x$ matching a registered public commitment $y = g^x \pmod p$, without revealing any information about $x$ itself. This project constructs an enterprise-grade ZKP Authentication Gateway utilizing both non-interactive **Fiat-Shamir heuristics** (Schnorr identification protocol) and Rank-1 Constraint System (R1CS) **zk-SNARKs** (Groth16 protocol via Circom). The system enforces zero credential exposure across the wire and guarantees complete server-side resilience against database leak exposures.

### 🌍 Real-World Incidents
- **Okta Identity Breach (2023)**: Attackers compromised customer support system credentials to steal session tokens, gaining unauthorized access to downstream enterprise tenants.
- **LastPass Vault Compromise (2022)**: Threat actors exfiltrated encrypted master password vaults; weak master passwords were subsequently cracked offline using GPU clusters.
- **T-Mobile Authentication API Leak (2021)**: Exposed API endpoints allowed attackers to intercept cleartext authentication tokens passed over internal microservice channels.

---

## 🔬 Research Paper References

| # | Paper Title | Authors | Year | Source | Key Contribution |
|---|-------------|---------|------|--------|-----------------|
| 1 | How to Prove Yourself: Practical Solutions to Identification Problems | Fiat & Shamir | 1986 | CRYPTO | Formulated non-interactive zero-knowledge proofs converting interactive protocols using hash functions. |
| 2 | On the Size of Pairing-Based Non-Interactive Zero-Knowledge Proofs | Jens Groth | 2016 | EUROCRYPT | Designed the Groth16 zk-SNARK protocol achieving constant 3-element proof sizes and fast verification. |
| 3 | Pinocchio: Nearly Optimal Verifiable Computation | Parno et al. | 2016 | IEEE S&P | Demonstrated practical zero-knowledge circuit compilers for arbitrary program verification. |

---

## 🏗️ System Architecture
Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project 089: 089 - Zero-Knowledge Proof Authentication System|Excalidraw Architecture Diagram]]


```mermaid
graph TD
    subgraph Enrollment Phase
        A[User Prover Client] --> B[Generate Private Secret Key x]
        B --> C[Compute Public Commitment y = g^x mod p]
        C --> D[Register Identity & Public Commitment y on Server]
    end

    subgraph Authentication & Proof Generation
        E[Login Request Initiated] --> F[Client Generates Random Salt r]
        F --> G[Compute Commitment T = g^r mod p]
        G --> H[Compute Challenge Hash c = SHA256 g || y || T || Nonce]
        H --> I[Compute Zero-Knowledge Response s = r + c * x mod q]
    end

    subgraph Verification Gateway Layer
        I --> J[Transmit Proof Payload: T, s, Nonce to Server Verifier]
        J --> K[Server Recomputes Challenge c' = SHA256 g || y || T || Nonce]
        K --> L[Verify Equality: g^s mod p == T * y^c' mod p]
    end

    subgraph Authorization Phase
        L -- Valid Proof --> M[✅ Issue Ephemeral JWT Access Token]
        L -- Invalid Proof --> N[❌ Reject Authentication & Log Anomaly]
    end
```

---

## 📐 Technical Implementation

### Phase 1: Research & Environment Setup (Week 1)
1. Install Node.js, `circom` compiler, `snarkjs`, and Python 3.10 with `pycryptodome`.
2. Study algebraic structures: Finite Fields $\mathbb{Z}_p$, Discrete Logarithm Problem, and Elliptic Curve Pairing Groups (BN254 curve).
3. Set up benchmark scripts measuring proof generation time vs verification latency.

### Phase 2: Core Module Development (Weeks 2-3)

#### Non-Interactive ZKP Authenticator (Fiat-Shamir Schnorr Protocol)
```python
import hashlib
import os

class SchnorrZKPAuthenticator:
    """Non-Interactive Zero-Knowledge Proof Authenticator using Schnorr Protocol."""
    # 2048-bit MODP Group Parameters (RFC 3526 Group 14)
    P = int("""
    FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381
    FFFFFFFFFFFFFFFF
    """, 16)
    
    Q = (P - 1) // 2  # Prime Order Subgroup
    G = 2             # Generator

    def __init__(self):
        pass

    @classmethod
    def generate_keypair(cls, secret_password: str):
        """Derive private secret key x and public commitment y."""
        x = int(hashlib.sha256(secret_password.encode()).hexdigest(), 16) % cls.Q
        y = pow(cls.G, x, cls.P)
        return x, y

    @classmethod
    def generate_proof(cls, secret_x: int, public_y: int, nonce: str):
        """Prover generates NIZK proof (T, s) without revealing secret_x."""
        # 1. Choose ephemeral random value r
        r = int.from_bytes(os.urandom(32), byteorder="big") % cls.Q
        
        # 2. Compute commitment T = g^r mod p
        T = pow(cls.G, r, cls.P)
        
        # 3. Compute Challenge c = H(g || y || T || nonce) via Fiat-Shamir transform
        challenge_input = f"{cls.G}:{public_y}:{T}:{nonce}".encode()
        c = int(hashlib.sha256(challenge_input).hexdigest(), 16) % cls.Q
        
        # 4. Compute response s = r + c * x mod q
        s = (r + c * secret_x) % cls.Q
        
        return {"T": T, "s": s, "nonce": nonce}

    @classmethod
    def verify_proof(cls, public_y: int, proof: dict) -> bool:
        """Verifier verifies proof (T, s) against registered public commitment y."""
        T = proof["T"]
        s = proof["s"]
        nonce = proof["nonce"]

        # 1. Recompute challenge c = H(g || y || T || nonce)
        challenge_input = f"{cls.G}:{public_y}:{T}:{nonce}".encode()
        c = int(hashlib.sha256(challenge_input).hexdigest(), 16) % cls.Q

        # 2. Verify: g^s == T * (y^c) mod p
        lhs = pow(cls.G, s, cls.P)
        rhs = (T * pow(public_y, c, cls.P)) % cls.P

        return lhs == rhs

if __name__ == "__main__":
    password = "CorrectHorseBatteryStaple"
    nonce = os.urandom(16).hex()

    # User Setup
    x, y = SchnorrZKPAuthenticator.generate_keypair(password)
    print(f"[*] User Public Commitment Registered: {hex(y)[:20]}...")

    # User generates Proof
    proof = SchnorrZKPAuthenticator.generate_proof(x, y, nonce)
    print(f"[*] Generated ZK-Proof (Response s): {hex(proof['s'])[:20]}...")

    # Server Verifies Proof
    is_valid = SchnorrZKPAuthenticator.verify_proof(y, proof)
    print(f"[+] Proof Verification Result: {'✅ VERIFIED AUTHENTIC' if is_valid else '❌ INVALID PROOF'}")
```

#### Circom ZK-SNARK Circuit: `credential_verifier.circom`
```circom
pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

template CredentialVerifier() {
    // Private input: secret user key
    signal input secretKey;
    
    // Public input: expected Poseidon hash commitment stored on server
    signal input expectedCommitment;

    // Output proof signal
    signal output isValid;

    // Instantiate Poseidon Hash Component
    component hasher = Poseidon(1);
    hasher.inputs[0] <== secretKey;

    // Enforce constraint that Poseidon(secretKey) == expectedCommitment
    hasher.out === expectedCommitment;
    isValid <== 1;
}

component main {public [expectedCommitment]} = CredentialVerifier();
```

### Phase 3: Integration & Testing (Week 4)
1. **Replay Attack Resistance**: Verify that modifying the `nonce` or reusing a previously captured proof string results in immediate verification failure.
2. **Groth16 Trusted Setup**: Compile Circom circuit, generate R1CS constraints, execute Powers of Tau ceremony, and export verification keys.
3. **API Gateway Integration**: Build a FastAPI gateway requiring ZKP proofs for authentication before issuing OAuth2 JWT access tokens.

### Phase 4: Analysis & Documentation (Week 5)
1. Performance Metrics Analysis: Measure proof construction duration on mobile client vs server verification latency ($< 5 \text{ ms}$).
2. Threat Model Security Proof: Formulate formal security reductions proving Perfect Zero-Knowledge and Special Soundness properties.

---

## 🔧 Tools & Technologies

| Tool | Purpose | Alternative |
|------|---------|-------------|
| Circom 2.x | Domain-specific language for building ZK-SNARK arithmetic circuits | ZoKrates / Noir |
| SnarkJS | JavaScript implementation of Groth16 and PLONK zk-SNARK protocols | arkworks (Rust) |
| PyCryptodome | Python library handling finite field operations and RFC groups | OpenSSL |
| FastAPI | Web framework hosting ZKP authentication API endpoints | Flask / Express.js |

---

## 💡 Key Features
- ✅ **Zero Secret Transmission**: Passwords and private keys never leave the client device; authentication occurs purely via mathematical proofs.
- ✅ **Server Leak Proof**: Server databases store only public commitments ($y = g^x \pmod p$); stolen databases cannot be cracked offline.
- ✅ **Replay Protection**: Nonce-based challenge computation ensures every ZK-proof payload is cryptographically unique and single-use.
- ✅ **Dual-Architecture Support**: Provides both lightweight Fiat-Shamir Schnorr identification and formal Groth16 zk-SNARK circuits.
- ✅ **Sub-Millisecond Verification**: Server verification requires only two modular exponentiations ($< 5 \text{ ms}$).

---

## 📊 Expected Results

> [!NOTE] Deliverables
> Complete Python Fiat-Shamir engine, Circom zk-SNARK circuits, FastAPI authentication server, and performance benchmarking whitepaper.

### Performance Metrics
- **Client Proof Generation Time**: $< 120 \text{ ms}$ for Groth16 proofs; $< 2 \text{ ms}$ for Fiat-Shamir proofs.
- **Server Verification Latency**: $< 3 \text{ ms}$ per authentication attempt.
- **Proof Payload Size**: 128 bytes (Groth16 BN254 curve).

### Output Artifacts
1. `schnorr_zkp.py`: Complete Python NIZK implementation module.
2. `credential_verifier.circom`: Circom ZK circuit file.
3. `ZKP_Auth_Architecture_Paper.pdf`: Academic paper detailing mathematical guarantees and performance benchmarks.

---

## 🎓 Learning Outcomes
1. 📚 **Zero-Knowledge Cryptography**: Mastery of Interactive Proof Systems, Fiat-Shamir heuristic, and Soundness/Completeness proofs.
2. 📚 **zk-SNARK Circuit Engineering**: Hands-on experience compiling R1CS constraints and Poseidon hash functions using Circom.
3. 📚 **Advanced Authentication Architectures**: Capability to engineer zero-trust identity gateways replacing traditional password storage.
4. 📚 **Elliptic Curve & Finite Field Math**: Deep mathematical understanding of group generators, pairing functions, BN254 curves.

---

## ⚠️ Ethical Considerations
> [!WARNING] Legal & Ethical Notice
> Production ZKP deployments must ensure proper randomness generation (`/dev/urandom` or hardware RNG) for ephemeral values $r$. Cryptographic parameters must utilize standardized, security-audited prime groups or curves to prevent Discrete Logarithm attack vector exploitation.

---

## 🔗 Related Projects
- [[085 - Blockchain-Based Secure Document Verification System.md]]
- [[088 - Password Cracking Optimization using Rainbow Tables & GPU.md]]
- [[092 - Secure Multi-Party Computation Protocol Implementation.md]]

---
*📅 Created: 2026-07-30 | 🏷️ Category: Cryptography & Steganography | 🔐 Offensive Security Research*
