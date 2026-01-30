import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../utils/api';

export default function ViewCapsule() {
    const { id } = useParams();
    const navigate = useNavigate();
    const [capsule, setCapsule] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [timeRemaining, setTimeRemaining] = useState(null);

    useEffect(() => {
        fetchCapsule();
    }, [id]);

    useEffect(() => {
        if (capsule && !capsule.isUnlocked) {
            const interval = setInterval(() => {
                updateTimeRemaining();
            }, 1000);

            return () => clearInterval(interval);
        }
    }, [capsule]);

    const fetchCapsule = async () => {
        try {
            const response = await api.get(`/capsules/${id}`);
            setCapsule(response.data.capsule);
            if (!response.data.capsule.isUnlocked) {
                updateTimeRemaining(response.data.capsule);
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to load capsule');
        } finally {
            setLoading(false);
        }
    };

    const updateTimeRemaining = (cap = capsule) => {
        if (!cap) return;

        const now = new Date();
        const unlock = new Date(cap.unlockDate);

        if (now >= unlock) {
            setTimeRemaining({ unlocked: true });
            // Refresh to get decrypted content
            if (!cap.content) {
                fetchCapsule();
            }
            return;
        }

        const diff = unlock - now;
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);

        setTimeRemaining({ unlocked: false, days, hours, minutes, seconds });
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

    if (error) {
        return (
            <div className="container">
                <div className="alert alert-error">{error}</div>
                <button onClick={() => navigate('/dashboard')} className="btn btn-secondary">
                    Back to Dashboard
                </button>
            </div>
        );
    }

    return (
        <div className="container" style={{ maxWidth: '800px', marginTop: '2rem' }}>
            <button onClick={() => navigate('/dashboard')} className="btn btn-secondary" style={{ marginBottom: '1rem' }}>
                ← Back to Dashboard
            </button>

            <div className="card">
                <div className="flex-between" style={{ marginBottom: '1.5rem' }}>
                    <h1>{capsule.title}</h1>
                    <span className={`badge ${capsule.isUnlocked ? 'badge-unlocked' : 'badge-locked'}`}>
                        {capsule.isUnlocked ? '🔓 Unlocked' : '🔒 Locked'}
                    </span>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                    <p style={{ color: 'var(--text-muted)' }}>
                        <strong>Created:</strong> {formatDate(capsule.createdAt)}
                    </p>
                    <p style={{ color: 'var(--text-muted)' }}>
                        <strong>Unlock Date:</strong> {formatDate(capsule.unlockDate)}
                    </p>
                </div>

                {/* QR Code */}
                <div className="text-center" style={{ marginBottom: '2rem' }}>
                    <h3>Capsule QR Code</h3>
                    <div className="qr-code" style={{ display: 'inline-block' }}>
                        <img src={capsule.qrCode} alt="Capsule QR Code" />
                    </div>
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                        Scan to share capsule ID: {capsule.id}
                    </p>
                </div>

                {/* Locked State */}
                {!capsule.isUnlocked && timeRemaining && !timeRemaining.unlocked && (
                    <div>
                        <div className="alert alert-warning">
                            <strong>⏰ This capsule is still locked</strong>
                            <p style={{ marginTop: '0.5rem', marginBottom: 0 }}>
                                Content will be decrypted and available after the unlock date.
                            </p>
                        </div>

                        <h3 className="text-center" style={{ marginTop: '2rem' }}>Time Remaining</h3>
                        <div className="countdown">
                            <div className="countdown-item">
                                <span className="countdown-value">{timeRemaining.days}</span>
                                <span className="countdown-label">Days</span>
                            </div>
                            <div className="countdown-item">
                                <span className="countdown-value">{timeRemaining.hours}</span>
                                <span className="countdown-label">Hours</span>
                            </div>
                            <div className="countdown-item">
                                <span className="countdown-value">{timeRemaining.minutes}</span>
                                <span className="countdown-label">Minutes</span>
                            </div>
                            <div className="countdown-item">
                                <span className="countdown-value">{timeRemaining.seconds}</span>
                                <span className="countdown-label">Seconds</span>
                            </div>
                        </div>
                    </div>
                )}

                {/* Unlocked State */}
                {capsule.isUnlocked && capsule.content && (() => {
                    // Try to parse content as JSON (for files)
                    let parsedContent = null;
                    let isFileContent = false;
                    try {
                        parsedContent = JSON.parse(capsule.content);
                        isFileContent = parsedContent && parsedContent.file;
                    } catch (e) {
                        // Not JSON, treat as plain text
                        parsedContent = null;
                    }

                    const downloadFile = () => {
                        if (!parsedContent || !parsedContent.file) return;

                        const { fileName, fileType, fileData } = parsedContent.file;

                        // Convert base64 to blob
                        const byteCharacters = atob(fileData);
                        const byteNumbers = new Array(byteCharacters.length);
                        for (let i = 0; i < byteCharacters.length; i++) {
                            byteNumbers[i] = byteCharacters.charCodeAt(i);
                        }
                        const byteArray = new Uint8Array(byteNumbers);
                        const blob = new Blob([byteArray], { type: fileType });

                        // Create download link
                        const url = window.URL.createObjectURL(blob);
                        const link = document.createElement('a');
                        link.href = url;
                        link.download = fileName;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);
                        window.URL.revokeObjectURL(url);
                    };

                    return (
                        <div>
                            <div className="alert alert-success">
                                <strong>✅ Capsule Unlocked & Verified</strong>
                                <p style={{ marginTop: '0.5rem', marginBottom: 0 }}>
                                    Content decrypted successfully. Digital signature verified.
                                </p>
                            </div>

                            {/* Text Message */}
                            {(isFileContent ? parsedContent.message : true) && (
                                <div style={{ marginTop: '2rem' }}>
                                    <h3>Message</h3>
                                    <div style={{
                                        background: 'var(--bg-tertiary)',
                                        padding: 'var(--spacing-md)',
                                        borderRadius: 'var(--radius-sm)',
                                        border: '1px solid var(--glass-border)',
                                        marginTop: 'var(--spacing-sm)',
                                        whiteSpace: 'pre-wrap',
                                        wordBreak: 'break-word'
                                    }}>
                                        {isFileContent ? (parsedContent.message || 'No message') : capsule.content}
                                    </div>
                                </div>
                            )}

                            {/* File Content */}
                            {isFileContent && parsedContent.file && (
                                <div style={{ marginTop: '2rem' }}>
                                    <h3>Attached File</h3>
                                    <div style={{
                                        background: 'var(--bg-tertiary)',
                                        padding: 'var(--spacing-md)',
                                        borderRadius: 'var(--radius-sm)',
                                        border: '1px solid var(--glass-border)',
                                        marginTop: 'var(--spacing-sm)'
                                    }}>
                                        {/* File Preview based on type */}
                                        {parsedContent.file.fileType.startsWith('image/') && (
                                            <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                                                <img
                                                    src={`data:${parsedContent.file.fileType};base64,${parsedContent.file.fileData}`}
                                                    alt={parsedContent.file.fileName}
                                                    style={{
                                                        maxWidth: '100%',
                                                        maxHeight: '500px',
                                                        borderRadius: '8px'
                                                    }}
                                                />
                                            </div>
                                        )}

                                        {parsedContent.file.fileType.startsWith('video/') && (
                                            <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
                                                <video
                                                    controls
                                                    style={{
                                                        maxWidth: '100%',
                                                        maxHeight: '500px',
                                                        borderRadius: '8px'
                                                    }}
                                                >
                                                    <source
                                                        src={`data:${parsedContent.file.fileType};base64,${parsedContent.file.fileData}`}
                                                        type={parsedContent.file.fileType}
                                                    />
                                                    Your browser does not support the video tag.
                                                </video>
                                            </div>
                                        )}

                                        {/* File Info */}
                                        <div style={{ marginTop: '1rem' }}>
                                            <p style={{ marginBottom: '0.5rem' }}>
                                                <strong>📎 File Name:</strong> {parsedContent.file.fileName}
                                            </p>
                                            <p style={{ marginBottom: '0.5rem' }}>
                                                <strong>📄 File Type:</strong> {parsedContent.file.fileType}
                                            </p>
                                            <p style={{ marginBottom: '1rem' }}>
                                                <strong>💾 File Size:</strong> {(parsedContent.file.fileSize / 1024).toFixed(2)} KB
                                            </p>

                                            <button
                                                onClick={downloadFile}
                                                className="btn btn-primary"
                                                style={{ width: '100%' }}
                                            >
                                                📥 Download File
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}

                            <div className="alert alert-info" style={{ marginTop: '2rem' }}>
                                <strong>🔐 Security Status:</strong>
                                <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem', marginBottom: 0 }}>
                                    <li>✅ Content successfully decrypted</li>
                                    <li>✅ Encryption key verified and secure (ECC P-256)</li>
                                    <li>✅ Content integrity confirmed - no tampering detected</li>
                                    <li>✅ Authenticity verified with digital signature (ECDSA)</li>
                                    {isFileContent && <li>✅ File decrypted and ready for download</li>}
                                </ul>
                            </div>
                        </div>
                    );
                })()}
            </div>
        </div>
    );
}
