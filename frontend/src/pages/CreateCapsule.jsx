import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';

export default function CreateCapsule() {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        title: '',
        content: '',
        unlockDate: ''
    });
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        // Validate unlock date is in the future
        const unlockDate = new Date(formData.unlockDate);
        const now = new Date();

        if (unlockDate <= now) {
            setError('Unlock date must be in the future');
            return;
        }

        setLoading(true);

        try {
            const response = await api.post('/capsules/create', {
                title: formData.title,
                content: formData.content,
                unlockDate: formData.unlockDate,
                type: 'text'
            });

            setSuccess('Time capsule created successfully! Redirecting...');
            setTimeout(() => {
                navigate('/dashboard');
            }, 2000);

        } catch (err) {
            setError(err.response?.data?.message || 'Failed to create capsule');
        } finally {
            setLoading(false);
        }
    };

    // Get minimum date (tomorrow)
    const getMinDate = () => {
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        return tomorrow.toISOString().slice(0, 16);
    };

    return (
        <div className="container" style={{ maxWidth: '700px', marginTop: '2rem' }}>
            <div className="card">
                <h1>Create Time Capsule</h1>
                <p style={{ marginBottom: '2rem' }}>
                    Store an encrypted message that will unlock at a future date
                </p>

                {error && <div className="alert alert-error">{error}</div>}
                {success && <div className="alert alert-success">{success}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label htmlFor="title">Capsule Title</label>
                        <input
                            type="text"
                            id="title"
                            name="title"
                            value={formData.title}
                            onChange={handleChange}
                            required
                            placeholder="e.g., My 2027 Goals"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="content">Message Content</label>
                        <textarea
                            id="content"
                            name="content"
                            value={formData.content}
                            onChange={handleChange}
                            required
                            placeholder="Write your message here... This will be encrypted using AES-256-CBC"
                            rows={8}
                        />
                        <small style={{ color: 'var(--text-muted)' }}>
                            Your message will be encrypted with AES-256-CBC. The encryption key will be secured with RSA-2048.
                        </small>
                    </div>

                    <div className="form-group">
                        <label htmlFor="unlockDate">Unlock Date & Time</label>
                        <input
                            type="datetime-local"
                            id="unlockDate"
                            name="unlockDate"
                            value={formData.unlockDate}
                            onChange={handleChange}
                            required
                            min={getMinDate()}
                        />
                        <small style={{ color: 'var(--text-muted)' }}>
                            The capsule will remain locked until this date and time
                        </small>
                    </div>

                    <div className="alert alert-info">
                        <strong>🔒 Security Features:</strong>
                        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem' }}>
                            <li>Content encrypted with AES-256-CBC</li>
                            <li>Encryption key protected with RSA-2048</li>
                            <li>Digital signature for integrity verification</li>
                            <li>SHA-256 hash for tamper detection</li>
                            <li>QR code generated for easy sharing</li>
                        </ul>
                    </div>

                    <div className="flex gap-1">
                        <button
                            type="button"
                            onClick={() => navigate('/dashboard')}
                            className="btn btn-secondary"
                            style={{ flex: 1 }}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="btn btn-primary"
                            disabled={loading}
                            style={{ flex: 1 }}
                        >
                            {loading ? 'Creating...' : 'Create Capsule'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
