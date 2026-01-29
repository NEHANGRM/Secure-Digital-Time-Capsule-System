import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

export default function Login() {
    const navigate = useNavigate();
    const { login } = useAuth();
    const [formData, setFormData] = useState({
        email: '',
        password: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [mfaRequired, setMfaRequired] = useState(false);
    const [tempToken, setTempToken] = useState('');
    const [mfaCode, setMfaCode] = useState('');

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await api.post('/auth/login', formData);

            // Check if MFA setup is required (first-time login)
            if (response.data.mfaSetupRequired) {
                // Store setup token and redirect to MFA setup
                localStorage.setItem('mfaSetupToken', response.data.setupToken);
                navigate('/mfa-setup', { state: { mandatory: true } });
                return;
            }

            // Check if MFA verification is required (returning user)
            if (response.data.mfaRequired) {
                setMfaRequired(true);
                setTempToken(response.data.tempToken);
                return;
            }

            // This should never happen now (MFA is mandatory)
            login(response.data.token, response.data.user);
            navigate('/dashboard');

        } catch (err) {
            setError(err.response?.data?.message || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    const handleMfaVerify = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        console.log('🔐 Submitting MFA verification...');
        console.log('   tempToken exists:', !!tempToken);
        console.log('   mfaCode:', mfaCode);

        try {
            const response = await api.post('/auth/verify-mfa', {
                tempToken,
                code: mfaCode.trim() // Ensure code is trimmed
            });

            console.log('✅ MFA verification response:', response.data);

            if (response.data.success && response.data.token) {
                console.log('✅ Token received, logging in...');
                login(response.data.token, response.data.user);

                // Force a small delay to ensure state is updated
                setTimeout(() => {
                    console.log('✅ Navigating to dashboard...');
                    navigate('/dashboard', { replace: true });
                }, 100);
            } else {
                console.log('❌ Unexpected response:', response.data);
                setError('Unexpected response from server');
            }

        } catch (err) {
            console.error('❌ MFA verification error:', err);
            console.error('   Response:', err.response?.data);
            setError(err.response?.data?.message || 'MFA verification failed');
        } finally {
            setLoading(false);
        }
    };

    if (mfaRequired) {
        return (
            <div className="container" style={{ maxWidth: '500px', marginTop: '3rem' }}>
                <div className="card">
                    <h1 className="text-center">🔐 MFA Verification</h1>
                    <p className="text-center" style={{ marginBottom: '2rem' }}>
                        Enter the code from your authenticator app
                    </p>

                    {error && <div className="alert alert-error">{error}</div>}

                    <form onSubmit={handleMfaVerify}>
                        <div className="form-group">
                            <label htmlFor="mfaCode">6-Digit Code</label>
                            <input
                                type="text"
                                id="mfaCode"
                                value={mfaCode}
                                onChange={(e) => setMfaCode(e.target.value)}
                                required
                                maxLength={6}
                                pattern="[0-9]{6}"
                                placeholder="000000"
                                style={{ textAlign: 'center', fontSize: '1.5rem', letterSpacing: '0.5rem' }}
                            />
                        </div>

                        <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
                            {loading ? 'Verifying...' : 'Verify Code'}
                        </button>
                    </form>

                    <button
                        onClick={() => setMfaRequired(false)}
                        className="btn btn-secondary"
                        style={{ width: '100%', marginTop: '1rem' }}
                    >
                        Back to Login
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="container" style={{ maxWidth: '500px', marginTop: '3rem' }}>
            <div className="card">
                <h1 className="text-center">Welcome Back</h1>
                <p className="text-center" style={{ marginBottom: '2rem' }}>
                    Login to access your time capsules
                </p>

                {error && <div className="alert alert-error">{error}</div>}

                <form onSubmit={handleLogin}>
                    <div className="form-group">
                        <label htmlFor="email">Email</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value={formData.email}
                            onChange={handleChange}
                            required
                            placeholder="Enter your email"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            value={formData.password}
                            onChange={handleChange}
                            required
                            placeholder="Enter your password"
                        />
                    </div>

                    <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
                        {loading ? 'Logging in...' : 'Login'}
                    </button>
                </form>

                <p className="text-center" style={{ marginTop: '1.5rem' }}>
                    Don't have an account? <Link to="/register" style={{ color: 'var(--accent-primary)' }}>Register here</Link>
                </p>
            </div>
        </div>
    );
}
