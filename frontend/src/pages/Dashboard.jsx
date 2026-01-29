import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

export default function Dashboard() {
    const { user } = useAuth();
    const [capsules, setCapsules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        fetchCapsules();
    }, []);

    const fetchCapsules = async () => {
        try {
            const response = await api.get('/capsules');
            setCapsules(response.data.capsules);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to load capsules');
        } finally {
            setLoading(false);
        }
    };

    const deleteCapsule = async (id) => {
        if (!confirm('Are you sure you want to delete this capsule?')) return;

        try {
            await api.delete(`/capsules/${id}`);
            setCapsules(capsules.filter(c => c.id !== id));
        } catch (err) {
            alert(err.response?.data?.message || 'Failed to delete capsule');
        }
    };

    const formatDate = (date) => {
        return new Date(date).toLocaleString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    if (loading) {
        return (
            <div className="container">
                <div className="spinner"></div>
            </div>
        );
    }

    return (
        <div className="container">
            <div className="flex-between" style={{ marginBottom: '2rem' }}>
                <div>
                    <h1>My Time Capsules</h1>
                    <p>Welcome back, {user?.username}!</p>
                </div>
                <Link to="/create" className="btn btn-primary">+ Create New Capsule</Link>
            </div>

            {error && <div className="alert alert-error">{error}</div>}

            {capsules.length === 0 ? (
                <div className="card text-center" style={{ padding: '3rem' }}>
                    <h2>No Time Capsules Yet</h2>
                    <p>Create your first time capsule to get started!</p>
                    <Link to="/create" className="btn btn-primary" style={{ marginTop: '1rem' }}>
                        Create Time Capsule
                    </Link>
                </div>
            ) : (
                <div className="grid grid-2">
                    {capsules.map((capsule) => (
                        <div key={capsule.id} className="card">
                            <div className="flex-between" style={{ marginBottom: '1rem' }}>
                                <h3>{capsule.title}</h3>
                                <span className={`badge ${capsule.isUnlocked ? 'badge-unlocked' : 'badge-locked'}`}>
                                    {capsule.isUnlocked ? '🔓 Unlocked' : '🔒 Locked'}
                                </span>
                            </div>

                            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                                Created: {formatDate(capsule.createdAt)}
                            </p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                                Unlocks: {formatDate(capsule.unlockDate)}
                            </p>

                            {!capsule.isUnlocked && capsule.timeRemaining && !capsule.timeRemaining.unlocked && (
                                <div className="countdown" style={{ marginTop: '1rem', gap: '0.5rem' }}>
                                    <div className="countdown-item">
                                        <span className="countdown-value">{capsule.timeRemaining.days}</span>
                                        <span className="countdown-label">Days</span>
                                    </div>
                                    <div className="countdown-item">
                                        <span className="countdown-value">{capsule.timeRemaining.hours}</span>
                                        <span className="countdown-label">Hours</span>
                                    </div>
                                    <div className="countdown-item">
                                        <span className="countdown-value">{capsule.timeRemaining.minutes}</span>
                                        <span className="countdown-label">Mins</span>
                                    </div>
                                </div>
                            )}

                            <div className="flex gap-1" style={{ marginTop: '1.5rem' }}>
                                <Link to={`/capsule/${capsule.id}`} className="btn btn-primary" style={{ flex: 1 }}>
                                    {capsule.isUnlocked ? 'View Content' : 'View Details'}
                                </Link>
                                <button
                                    onClick={() => deleteCapsule(capsule.id)}
                                    className="btn btn-danger"
                                >
                                    Delete
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            <div className="card" style={{ marginTop: '2rem' }}>
                <h3>Security Features</h3>
                <div className="grid grid-3" style={{ marginTop: '1rem' }}>
                    <div>
                        <h4 style={{ color: 'var(--accent-primary)' }}>🔐 Encrypted</h4>
                        <p style={{ fontSize: '0.9rem' }}>AES-256-CBC + RSA hybrid encryption</p>
                    </div>
                    <div>
                        <h4 style={{ color: 'var(--accent-success)' }}>✅ Verified</h4>
                        <p style={{ fontSize: '0.9rem' }}>Digital signatures ensure integrity</p>
                    </div>
                    <div>
                        <h4 style={{ color: 'var(--accent-secondary)' }}>⏰ Time-Locked</h4>
                        <p style={{ fontSize: '0.9rem' }}>Unlocks only after chosen date</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
