# Models Directory

This directory stores trained ML models for Cipher Aegis.

## Model Files

- **`aegis_brain.pkl`**: Trained Isolation Forest model
  - Created during training mode
  - Contains: model, scaler, metadata
  - Pickle format (Python serialization)

## Model Structure

The `.pkl` file contains:
```python
{
    'model': IsolationForest instance,
    'scaler': StandardScaler instance,
    'contamination': float,
    'n_estimators': int,
    'max_samples': int,
    'training_timestamp': float,
    'training_samples': int
}
```

## Creating a Model

```bash
# Run main.py without existing model
python main.py

# Follow prompts for training mode
# Model will be saved to this directory
```

## Model Info

View model metadata:
```python
from ml.model import AegisBrain

brain = AegisBrain()
brain.load()
print(brain.get_model_info())
```

## Backup Models

```bash
# Create backup
cp data/models/aegis_brain.pkl data/models/aegis_brain_backup_$(date +%Y%m%d).pkl

# Restore from backup
cp data/models/aegis_brain_backup_YYYYMMDD.pkl data/models/aegis_brain.pkl
```

## Retraining

To retrain the model:
1. Delete or rename existing model
2. Run `python main.py`
3. Select "yes" for training mode
4. Generate normal traffic for 60 seconds

## Model Performance

Model accuracy depends on:
- **Training data quality**: Only benign traffic
- **Training data volume**: More samples = better performance
- **Traffic diversity**: Various protocols and patterns
- **Contamination parameter**: Expected anomaly rate (default: 0.1)

## Troubleshooting

**Model won't load:**
- Ensure file exists and is not corrupted
- Check file permissions
- Verify Python/sklearn version compatibility

**Poor detection:**
- Retrain with more diverse traffic
- Increase training duration
- Adjust contamination parameter
