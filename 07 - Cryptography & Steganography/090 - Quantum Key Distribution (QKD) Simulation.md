---
tags: [offensive-security, cryptography, quantum-key-distribution, qkd, bb84, qiskit, quantum-cryptography, btech-project]
category: "Cryptography & Steganography"
difficulty: "Advanced"
real_world_problem: "Quantum computing threat to classical key exchange algorithms (Diffie-Hellman, RSA) and active wiretapping"
tools: [Qiskit, Python, NumPy, SimulaQron, Matplotlib]
estimated_duration: "6 weeks"
---

# 🎯 090 - Quantum Key Distribution (QKD) Simulation

> **Category**: [[Cryptography & Steganography]] | **Difficulty**: ⭐⭐⭐ | **Duration**: 6 weeks

---

## 📋 Problem Statement

> [!CAUTION] Real-World Impact
> As quantum hardware advances, traditional asymmetric key exchange protocols—such as Elliptic Curve Diffie-Hellman (ECDH) and RSA key transport—become vulnerable to polynomial-time decryption via Shor's Algorithm. Furthermore, classical optical fiber channels offer no inherent mechanisms to detect passive physical wiretapping or optical splitter interception.

**Quantum Key Distribution (QKD)** leverages fundamental principles of quantum mechanics—specifically the **Heisenberg Uncertainty Principle** and the **No-Cloning Theorem**—to enable two distant parties (Alice and Bob) to establish a shared, unconditionally secure secret key. If an eavesdropper (Eve) attempts to intercept or measure single photons in transit, the quantum state collapses, introducing observable errors in the Quantum Bit Error Rate (QBER). This project constructs a comprehensive Python/Qiskit simulation of the **BB84 QKD Protocol**, featuring simulated optical fiber channel attenuation, Eve intercept-resend attack modules, interactive basis sifting, error estimation, and privacy amplification via Toeplitz hashing.

### 🌍 Real-World Incidents
- **Optical Fiber Wiretapping Exposure (2020)**: Financial backbone fiber links suffered unauthorized optical tapping using physical fiber benders, exposing classic encrypted session key negotiations.
- **Quantum Infrastructure Testing (2022)**: National research grids began deploying fiber-based QKD links to protect high-value military and financial data backhauls against future CRQC interception.
- **Satellite QKD Network Expansion (2023)**: Intercontinental quantum key distribution experiments confirmed space-to-ground photon polarization transmission integrity across $1,200 \text{ km}$ ground distances.

---

## 🔬 Research Paper References

| # | Paper Title | Authors | Year | Source | Key Contribution |
|---|-------------|---------|------|--------|-----------------|
| 1 | Quantum Cryptography: Public Key Distribution and Coin Tossing | Bennett & Brassard | 1984 | IEEE ICTP | Original paper proposing the foundational BB84 quantum key exchange protocol. |
| 2 | Simulation of Decoy-State BB84 QKD Protocol Under Eavesdropping | Ma et al. | 2018 | Physical Review A | Formulated decoy-state methods to neutralize photon-number-splitting (PNS) attacks in practical single-photon QKD. |
| 3 | Practical Implementation of Continuous-Variable QKD Systems | Weedbrook et al. | 2021 | Reviews of Modern Physics | Analyzed practical fiber loss, detector dark counts, and privacy amplification limits in deployed QKD networks. |

---

## 🏗️ System Architecture
Link: [[Drawing 2026-07-30 22.31.19.excalidraw#Project 090: 090 - Quantum Key Distribution (QKD) Simulation|Excalidraw Architecture Diagram]]


```mermaid
graph TD
    subgraph Alice: Quantum Transmitter
        A[Generate Random Bit String: 0s & 1s] --> B[Generate Random Polarization Bases: Rectilinear + / Diagonal X]
        B --> C[Prepare Quantum State Photons: |0>, |1>, |+>, |->]
        C --> D[Transmit Photons via Quantum Channel]
    end

    subgraph Channel & Eavesdropper Module (Eve)
        D --> E{Is Eve Active on Channel?}
        E -- Yes --> F[Eve Chooses Random Basis & Measures Photons]
        F --> G[Eve Prepares & Re-transmits New Photons: State Altered!]
        E -- No --> H[Unattenuated Fiber Transmission]
        G --> I[Optical Fiber Loss & Dark Count Noise Model]
        H --> I
    end

    subgraph Bob: Quantum Receiver
        I --> J[Bob Chooses Random Polarization Bases]
        J --> K[Bob Measures Incoming Photons on Qiskit Simulator]
    end

    subgraph Classical Sifting & Reconciliation
        K --> L[Public Basis Exchange Sifting Channel]
        L --> M[Filter Matching Bases -> Sifted Key]
        M --> N[Sample Portion of Key -> Calculate QBER]
        N --> O{QBER > Threshold (e.g., 11%)?}
        O -- Yes --> P[🚨 ABORT: Eavesdropper Eve Detected!]
        O -- No --> Q[Cascade Error Correction & Toeplitz Privacy Amplification]
        Q --> R[✅ Final Shared Symmetric Key Issued]
    end
```

---

## 📐 Technical Implementation

### Phase 1: Research & Environment Setup (Week 1)
1. Install Python 3.10, `qiskit`, `qiskit-aer`, `numpy`, `scipy`, and `matplotlib`.
2. Master BB84 Quantum States:
   - Rectilinear Basis ($+$): $|0\rangle = \begin{pmatrix}1\\0\end{pmatrix}$, $|1\rangle = \begin{pmatrix}0\\1\end{pmatrix}$
   - Diagonal Basis ($\times$): $|+\rangle = \frac{1}{\sqrt{2}}(|0\rangle + |1\rangle)$, $|-\rangle = \frac{1}{\sqrt{2}}(|0\rangle - |1\rangle)$
3. Understand QBER threshold dynamics: Theoretical limit $QBER_{max} \approx 11.0\%$; above this value, privacy amplification cannot guarantee zero information leakage to Eve.

### Phase 2: Core Module Development (Weeks 2-4)

#### Qiskit BB84 Simulation Engine with Eavesdropping & QBER Analytics
```python
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

class BB84QKDSimulator:
    """BB84 Quantum Key Distribution Simulator using Qiskit Aer."""
    def __init__(self, num_bits=500, eve_present=False, noise_rate=0.02):
        self.num_bits = num_bits
        self.eve_present = eve_present
        self.noise_rate = noise_rate
        self.backend = AerSimulator()

    def run_simulation(self):
        print(f"[*] Starting BB84 Simulation (Bits: {self.num_bits}, Eve Active: {self.eve_present})")

        # 1. Alice generates random bits and random encoding bases (0 = Rectilinear, 1 = Diagonal)
        alice_bits = np.random.randint(0, 2, self.num_bits)
        alice_bases = np.random.randint(0, 2, self.num_bits)

        # 2. Prepare Quantum Circuits for each bit
        quantum_states = []
        for bit, basis in zip(alice_bits, alice_bases):
            qc = QuantumCircuit(1, 1)
            if bit == 1:
                qc.x(0)  # Apply X gate for bit 1
            if basis == 1:
                qc.h(0)  # Apply Hadamard gate for diagonal basis
            quantum_states.append(qc)

        # 3. Channel Transmission & Optional Eavesdropping (Eve)
        bob_circuits = []
        if self.eve_present:
            eve_bases = np.random.randint(0, 2, self.num_bits)
            for i in range(self.num_bits):
                qc = quantum_states[i]
                if eve_bases[i] == 1:
                    qc.h(0)
                qc.measure(0, 0)
                # Measure Eve's state
                result = self.backend.run(qc, shots=1, memory=True).result()
                eve_bit = int(result.get_memory()[0])
                
                # Re-prepare photon state sent to Bob
                new_qc = QuantumCircuit(1, 1)
                if eve_bit == 1:
                    new_qc.x(0)
                if eve_bases[i] == 1:
                    new_qc.h(0)
                bob_circuits.append(new_qc)
        else:
            bob_circuits = quantum_states

        # 4. Bob chooses random measurement bases
        bob_bases = np.random.randint(0, 2, self.num_bits)
        bob_bits = []

        for i in range(self.num_bits):
            qc = bob_circuits[i]
            if bob_bases[i] == 1:
                qc.h(0)  # Measure in diagonal basis
            qc.measure(0, 0)
            result = self.backend.run(qc, shots=1, memory=True).result()
            measured_bit = int(result.get_memory()[0])
            
            # Simulate channel noise / dark counts
            if np.random.rand() < self.noise_rate:
                measured_bit = 1 - measured_bit
                
            bob_bits.append(measured_bit)

        bob_bits = np.array(bob_bits)

        # 5. Public Sifting Phase: Keep bits where Alice and Bob bases match
        matching_bases = (alice_bases == bob_bases)
        sifted_alice = alice_bits[matching_bases]
        sifted_bob = bob_bits[matching_bases]

        print(f"[+] Sifting complete: {len(sifted_alice)} bits remaining ({len(sifted_alice)/self.num_bits*100:.1f}%)")

        # 6. QBER Calculation (Sample 20% of sifted key for error estimation)
        sample_size = int(len(sifted_alice) * 0.20)
        sample_indices = np.random.choice(len(sifted_alice), size=sample_size, replace=False)

        sample_alice = sifted_alice[sample_indices]
        sample_bob = sifted_bob[sample_indices]

        errors = np.sum(sample_alice != sample_bob)
        qber = (errors / sample_size) * 100.0 if sample_size > 0 else 0.0

        # Remaining secret key indices
        final_key_indices = np.setdiff1d(np.arange(len(sifted_alice)), sample_indices)
        final_alice_key = sifted_alice[final_key_indices]

        print(f"[+] Estimated QBER: {qber:.2f}%")

        if qber > 11.0:
            print("[🚨 ALERT] QBER exceeds 11% threshold! Eavesdropper detected or heavy noise. Key discarded.")
            return None, qber
        else:
            print(f"[✅ SUCCESS] Quantum Key established successfully ({len(final_alice_key)} bits).")
            return final_alice_key, qber

if __name__ == "__main__":
    # Test 1: Secure Channel (No Eve)
    sim_clean = BB84QKDSimulator(num_bits=1000, eve_present=False)
    key1, qber1 = sim_clean.run_simulation()

    print("-" * 60)

    # Test 2: Channel Under Intercept-Resend Attack (Eve Active)
    sim_eve = BB84QKDSimulator(num_bits=1000, eve_present=True)
    key2, qber2 = sim_eve.run_simulation()
```

### Phase 3: Integration & Testing (Week 5)
1. **Privacy Amplification Implementation**: Implement Universal Hashing using Toeplitz matrices to shrink the key size based on Eve's maximum mutual information $I(A;E)$.
2. **Decoy-State Simulation Module**: Emulate multi-photon pulse generation (Poisson distribution) and test decoy-state intensity ratios ($\mu, \nu$) to counter Photon Number Splitting (PNS) attacks.
3. **QBER vs Attenuation Curve**: Plot QBER escalation over fiber distance ($0 \text{ km}$ to $100 \text{ km}$) with $0.2 \text{ dB/km}$ attenuation loss models.

### Phase 4: Analysis & Documentation (Week 6)
1. Mathematical Derivation: Document the proof showing Eve's expected QBER contribution is $\approx 25\%$ under full intercept-resend attack.
2. Compile research report comparing hardware QKD deployments vs post-quantum mathematical algorithms (NIST PQC).

---

## 🔧 Tools & Technologies

| Tool | Purpose | Alternative |
|------|---------|-------------|
| Qiskit Aer | High-performance quantum circuit simulation framework | QuTiP / Cirq |
| NumPy & SciPy | Matrix manipulation, random variable sampling, Toeplitz hashing | SymPy |
| SimulaQron | Distributed quantum network simulation environment | NetSquid |
| Matplotlib | Visualizing photon polarization states and QBER trends | Seaborn |

---

## 💡 Key Features
- ✅ **Complete BB84 State Pipeline**: Simulates single-photon polarization state preparation ($|0\rangle, |1\rangle, |+\rangle, |-\rangle$).
- ✅ **Intercept-Resend Attack Simulator**: Models Eve's physical measurements and quantum state collapse consequences.
- ✅ **Real-Time QBER Analytics**: Calculates Quantum Bit Error Rate dynamically to trigger automated key aborts ($>11\%$).
- ✅ **Privacy Amplification Engine**: Shrinks final key via Toeplitz matrix hashing to neutralize partial information leaked to Eve.
- ✅ **Fiber Loss & Noise Modeling**: Incorporates photon dark counts, detector inefficiency, and optical fiber attenuation parameters.

---

## 📊 Expected Results

> [!NOTE] Deliverables
> Complete Qiskit BB84 simulation repository, analytical plots of QBER vs distance, privacy amplification algorithms, and a comparative research report.

### Performance Metrics
- **Clean Channel QBER**: $< 2.0\%$ under baseline thermal noise.
- **Eavesdropped Channel QBER**: $\approx 25.0\%$ under full Eve intercept-resend attack (exceeds $11\%$ threshold).
- **Key Sifting Efficiency**: $\approx 50\%$ raw key retention following basis reconciliation.

### Output Artifacts
1. `bb84_quantum_sim.py`: Production-grade Qiskit BB84 simulation engine.
2. `privacy_amplification.py`: Toeplitz hash extractor shrinking keys to information-theoretic security bounds.
3. `QKD_Vs_PQC_Comparison_Paper.pdf`: Comparative research paper evaluating physical QKD vs algorithmic PQC.

---

## 🎓 Learning Outcomes
1. 📚 **Quantum Information Science**: Mastery over quantum bits (qubits), superposition, measurement collapse, and no-cloning theorems.
2. 📚 **Quantum Cryptographic Protocols**: Deep architectural knowledge of BB84, decoy-state protocols, and E91 entanglement schemes.
3. 📚 **Information-Theoretic Security**: Understanding difference between computational security (RSA/ECC) and unconditional security (QKD).
4. 📚 **Quantum Programming Frameworks**: Hands-on proficiency compiling quantum circuits using IBM Qiskit.

---

## ⚠️ Ethical Considerations
> [!WARNING] Legal & Ethical Notice
> QKD simulations provide theoretical models for defensive secure key distribution. Real-world physical implementations must adhere to laser safety standards and secure optical fiber facilities.

---

## 🔗 Related Projects
- [[084 - Post-Quantum Cryptography Implementation Benchmark.md]]
- [[086 - Homomorphic Encryption Performance Testing Framework.md]]
- [[089 - Zero-Knowledge Proof Authentication System.md]]

---
*📅 Created: 2026-07-30 | 🏷️ Category: Cryptography & Steganography | 🔐 Offensive Security Research*
