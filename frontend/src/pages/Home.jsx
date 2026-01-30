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
                    Experience peace of mind with bank-level security.
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
                    <h3>Military-Grade Encryption</h3>
                    <p>Your messages are protected with bank-level security</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>✍️</h2>
                    <h3>Tamper-Proof Security</h3>
                    <p>Digital signatures ensure your capsule hasn't been modified</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>🔑</h2>
                    <h3>Two-Factor Authentication</h3>
                    <p>Extra layer of security to protect your account</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>⏰</h2>
                    <h3>Time-Based Locks</h3>
                    <p>Content unlocks only after your chosen date</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>👥</h2>
                    <h3>Role-Based Access</h3>
                    <p>Smart permission system with user, admin, and auditor roles</p>
                </div>

                <div className="card text-center">
                    <h2 style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>📊</h2>
                    <h3>Complete Audit Trail</h3>
                    <p>Every action is logged for security and transparency</p>
                </div>
            </div>

            <div className="card" style={{ marginTop: '4rem' }}>
                <h2 className="text-center">How We Keep Your Capsules Secure</h2>
                <div className="grid grid-2" style={{ marginTop: '2rem' }}>
                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>🛡️ Secure Authentication</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Protected password storage</li>
                            <li>Secure login sessions</li>
                            <li>Optional two-factor authentication</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>👮 Smart Access Control</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Role-based permissions</li>
                            <li>Controlled data access</li>
                            <li>Principle of least privilege</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>🔐 Military-Grade Encryption</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Bank-level content encryption</li>
                            <li>Secure key management</li>
                            <li>Multi-layer security architecture</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>✅ Integrity Protection</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Tamper detection system</li>
                            <li>Content verification</li>
                            <li>Authenticity guarantees</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>✍️ Digital Signatures</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>Proof of authenticity</li>
                            <li>Signature verification</li>
                            <li>Non-repudiation guarantee</li>
                        </ul>
                    </div>

                    <div>
                        <h3 style={{ color: 'var(--accent-primary)' }}>📱 Easy Sharing</h3>
                        <ul style={{ marginLeft: '1.5rem' }}>
                            <li>QR code generation</li>
                            <li>Secure data encoding</li>
                            <li>Simple capsule sharing</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    );
}
