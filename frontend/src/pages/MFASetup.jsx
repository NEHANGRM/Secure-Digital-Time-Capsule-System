import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

export default function MFASetup() {
    const navigate = useNavigate();
    const location = useLocation();
    const { login } = useAuth();
    const [step, setStep] = useState(1);
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [userId, setUserId] = useState('');
    const [verificationCode, setVerificationCode] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [loading, setLoading] = useState(false);
    const [isMandatory, setIsMandatory] = useState(false);
    const [setupToken, setSetupToken] = useState('');

    useEffect(() => {
        // Check if this is mandatory MFA setup
        const mandatory = location.state?.mandatory || false;
        setIsMandatory(mandatory);

        // Get setup token if it exists
        const token = localStorage.getItem('mfaSetupToken');
        if (token) {
            setSetupToken(token);
        }
    }, [location]);

    const setupMFA = async () => {
        setLoading(true);
        setError('');

        try {
            const payload = setupToken ? { setupToken } : {};
            const response = await api.post('/auth/setup-mfa', payload);
            setQrCode(response.data.qrCode);
            setSecret(response.data.secret);
            setUserId(response.data.userId);
            setStep(2);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to setup MFA');
        } finally {
            setLoading(false);
        }
    };

    const enableMFA = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const payload = {
                code: verificationCode,
                setupToken: setupToken || undefined,
                userId: userId || undefined
            };

            const response = await api.post('/auth/enable-mfa', payload);

            // If we got a token back, log the user in automatically
            if (response.data.token) {
                localStorage.removeItem('mfaSetupToken'); // Clean up
                login(response.data.token, response.data.user);
                setSuccess('MFA enabled successfully! Redirecting to dashboard...');
                setTimeout(() => {
                    navigate('/dashboard');
                }, 2000);
            } else {
                setSuccess('MFA enabled successfully! Redirecting...');
                setTimeout(() => {
                    navigate('/dashboard');
                }, 2000);
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to enable MFA');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="container" style={{ maxWidth: '600px', marginTop: '2rem' }}>
            <div className="card">
                <h1>🔐 Multi-Factor Authentication Setup</h1>
                {isMandatory && (
                    <div className="alert alert-warning" style={{ marginBottom: '1rem' }}>
                        <strong>⚠️ MFA is Required</strong>
                        <p style={{ marginTop: '0.5rem', marginBottom: 0 }}>
                            For your security, Multi-Factor Authentication is mandatory for all users.
                            You must complete this setup to access your account.
                        </p>
                    </div>
                )}
                <p style={{ marginBottom: '2rem' }}>
                    Add an extra layer of security to your account
                </p>

                {error && <div className="alert alert-error">{error}</div>}
                {success && <div className="alert alert-success">{success}</div>}

                {step === 1 && (
                    <div>
                        <div className="alert alert-info">
                            <strong>What is MFA?</strong>
                            <p style={{ marginTop: '0.5rem', marginBottom: 0 }}>
                                Multi-Factor Authentication adds an extra security layer by requiring a time-based code
                                from your authenticator app (like Google Authenticator or Authy) in addition to your password.
                            </p>
                        </div>

                        <h3>Benefits:</h3>
                        <ul style={{ marginLeft: '1.5rem', marginBottom: '2rem' }}>
                            <li>Protects against password theft</li>
                            <li>Prevents unauthorized access even if password is compromised</li>
                            <li>Uses TOTP (Time-based One-Time Password) standard</li>
                            <li>Works offline with authenticator apps</li>
                        </ul>

                        <button
                            onClick={setupMFA}
                            className="btn btn-primary"
                            style={{ width: '100%' }}
                            disabled={loading}
                        >
                            {loading ? 'Setting up...' : 'Start MFA Setup'}
                        </button>

                        {!isMandatory && (
                            <button
                                onClick={() => navigate('/dashboard')}
                                className="btn btn-secondary"
                                style={{ width: '100%', marginTop: '1rem' }}
                            >
                                Skip for Now
                            </button>
                        )}
                    </div>
                )}

                {step === 2 && (
                    <div>
                        <h3>Step 1: Scan QR Code</h3>
                        <p>Open your authenticator app and scan this QR code:</p>

                        <div className="text-center">
                            <div className="qr-code" style={{ display: 'inline-block' }}>
                                <img src={qrCode} alt="MFA QR Code" />
                            </div>
                        </div>

                        <div className="alert alert-warning">
                            <strong>Can't scan?</strong>
                            <p style={{ marginTop: '0.5rem' }}>
                                Manually enter this secret key: <code style={{
                                    background: 'var(--bg-tertiary)',
                                    padding: '0.25rem 0.5rem',
                                    borderRadius: '4px',
                                    wordBreak: 'break-all'
                                }}>{secret}</code>
                            </p>
                        </div>

                        <h3 style={{ marginTop: '2rem' }}>Step 2: Enter Verification Code</h3>
                        <form onSubmit={enableMFA}>
                            <div className="form-group">
                                <label htmlFor="code">6-Digit Code from Authenticator App</label>
                                <input
                                    type="text"
                                    id="code"
                                    value={verificationCode}
                                    onChange={(e) => setVerificationCode(e.target.value)}
                                    required
                                    maxLength={6}
                                    pattern="[0-9]{6}"
                                    placeholder="000000"
                                    style={{ textAlign: 'center', fontSize: '1.5rem', letterSpacing: '0.5rem' }}
                                />
                            </div>

                            <button
                                type="submit"
                                className="btn btn-primary"
                                style={{ width: '100%' }}
                                disabled={loading}
                            >
                                {loading ? 'Verifying...' : 'Enable MFA'}
                            </button>
                        </form>

                        <button
                            onClick={() => navigate('/dashboard')}
                            className="btn btn-secondary"
                            style={{ width: '100%', marginTop: '1rem' }}
                        >
                            Cancel
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
