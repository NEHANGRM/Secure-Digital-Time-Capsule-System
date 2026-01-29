import { Link } from 'react-router-dom';

export default function Home() {
    return (
        <div className="container">
            <div style={{ textAlign: 'center', marginTop: '4rem', marginBottom: '4rem' }}>
                <h1 style={{ fontSize: '3rem', marginBottom: '1rem' }}>
                    🔐 Secure Digital Time Capsule System
                </h1>
                <p style={{ fontSize: '1.25rem', color: 'var(--text-secondary)', maxWidth: '700px', margin: '0 auto 2rem' }}>
                    Store encrypted messages and files that unlock at a future date.
                    Built with enterprise-grade security for cybersecurity demonstration.
                </p>

                <div className="flex gap-2" style={{ justifyContent: 'center', marginTop: '2rem' }}>
                    <Link to="/register" className="btn btn-primary" style={{ fontSize: '1.1rem', padding: '1rem 2rem' }}>
                        Get Started
                    </Link>
                    <Link to="/login" className="btn btn-secondary" style={{ fontSize: '1.1rem', padding: '1rem 2rem' }}>
                        Login
                    </Link>
                </div>
            </div>

            <div className="grid grid-3" style={{ marginTop: '4rem' }}>
                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🔒</h2>
                    <h3>Hybrid Encryption</h3>
                    <p>AES-256-CBC for content + RSA-2048 for key exchange</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>✍️</h2>
                    <h3>Digital Signatures</h3>
                    <p>RSA signatures ensure authenticity and integrity</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🔑</h2>
                    <h3>Multi-Factor Auth</h3>
                    <p>TOTP-based MFA for enhanced security</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>⏰</h2>
                    <h3>Time-Based Locks</h3>
                    <p>Content unlocks only after chosen date</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>👥</h2>
                    <h3>Role-Based Access</h3>
                    <p>User, Admin, and Auditor roles with permissions</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>📊</h2>
                    <h3>Audit Logging</h3>
                    <p>Complete trail of all security events</p>
                </div>
            </div>

            <div className="card" style={{ marginTop: '4rem' }}>
                <h2 className="text-center">Security Concepts Implemented</h2>
                <div className="grid grid-2" style={{ marginTop: '2rem' }}>
                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>1️⃣ Authentication</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Bcrypt password hashing with salt</li>
                            <li>JWT token-based sessions</li>
                            <li>TOTP multi-factor authentication</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>2️⃣ Authorization</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Role-Based Access Control (RBAC)</li>
                            <li>Access Control Matrix</li>
                            <li>Principle of least privilege</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>3️⃣ Encryption</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>AES-256-CBC symmetric encryption</li>
                            <li>RSA-2048 asymmetric encryption</li>
                            <li>Hybrid encryption architecture</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>4️⃣ Hashing</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>SHA-256 content hashing</li>
                            <li>Integrity verification</li>
                            <li>Tamper detection</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>5️⃣ Digital Signatures</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>RSA signature creation</li>
                            <li>Signature verification</li>
                            <li>Non-repudiation</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>6️⃣ Encoding</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>QR code generation</li>
                            <li>Base64 encoding</li>
                            <li>Easy capsule sharing</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    );
}
