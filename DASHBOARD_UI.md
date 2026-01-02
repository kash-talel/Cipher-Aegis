# Cipher Aegis Dashboard - UI Overview

## Dashboard Layout

The Cipher Aegis dashboard features a cyberpunk-inspired design with a dark gradient background and neon accents.

### Color Scheme
- **Background**: Dark blue gradient (#0f0f23 → #1a1a2e)
- **Primary Accent**: Cyan (#00d9ff) - Used for headers and highlights
- **Threat Indicators**:
  - 🔴 **HIGH**: #ff006e (Hot Pink)
  - 🟠 **MEDIUM**: #fb8500 (Orange)
  - 🔵 **LOW**: #4cc9f0 (Cyan)
- **Text**:
  - Primary: #f1f1f1 (Light Gray)
  - Secondary: #a8dadc (Muted Cyan)

---

## Components Breakdown

### 1. Header Section
```
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                    🛡️ CIPHER AEGIS                                ║
║            Next-Generation Intrusion Detection System             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
```

### 2. Metrics Row (Top)
```
┌─────────────────────┬─────────────────────┬─────────────────────┐
│  📊 Total Packets   │ 🚨 Anomalies Det.   │ 🎯 Threat Level     │
│                     │                     │                     │
│     12,453          │        142          │      MEDIUM         │
│   (+89 flows)       │   (8 recent)       │   ⚠️ (orange glow)  │
└─────────────────────┴─────────────────────┴─────────────────────┘
```

### 3. Traffic Chart (Center)
```
┌─────────────────────────────────────────────────────────────────┐
│  📈 Real-Time Traffic Analysis                                  │
│                                                                 │
│  [Chart with dual y-axis]                                       │
│  - Bar Chart (Blue): Traffic Volume (packets per flow)         │
│  - Line Chart (Red): Anomaly Score (0-1)                       │
│  - Red Markers: Detected anomalies                             │
│  - Green Markers: Normal traffic                               │
│                                                                 │
│  X-Axis: Time (HH:MM:SS)                                        │
│  Y-Axis Left: Packet Count                                     │
│  Y-Axis Right: Anomaly Score                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 4. Red Alerts Table (Bottom)
```
┌─────────────────────────────────────────────────────────────────┐
│  🔴 Recent Red Alerts (Latest 10 Anomalies)                     │
├─────────────────────────────────────────────────────────────────┤
│ Time       Src IP          Dst IP       Port  Proto Score Threat│
├─────────────────────────────────────────────────────────────────┤
│ 12:34:56  192.168.1.100  93.184.216.34  443  TCP  0.8523  HIGH │
│ 12:32:15  192.168.1.101  8.8.8.8         53   UDP  0.7234  MED  │
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

- **Color Coding**:
  - HIGH rows: Light red background (#ff006e with 20% opacity)
  - MEDIUM rows: Light orange background (#fb8500 with 20% opacity)
  - LOW rows: Light cyan background (#4cc9f0 with 10% opacity)

### 5. Sidebar (Right)
```
╔═══════════════════════════════╗
║  ⚙️ Dashboard Controls        ║
║                               ║
║  🔄 Auto-refresh: [✓]         ║
║  Interval: [━━●━━] 5s         ║
║                               ║
╠═══════════════════════════════╣
║  📋 System Logs               ║
║                               ║
║  12:34:56                     ║
║  ℹ️ INFO                       ║
║  Sentinel started             ║
║                               ║
║  12:35:23                     ║
║  ⚠️ WARNING                     ║
║  Anomaly detected             ║
║  Score: 0.853                 ║
║                               ║
╠═══════════════════════════════╣
║  📊 System Statistics         ║
║                               ║
║  Database: 234.5 KB           ║
║  Total Flows: 1,234           ║
║                               ║
║  Threat Distribution:         ║
║  ⬤ HIGH: 12                   ║
║  ⬤ MEDIUM: 34                 ║
║  ⬤ LOW: 96                    ║
╚═══════════════════════════════╝
```

---

## Interactive Features

### Auto-Refresh
- **Toggle**: Checkbox in sidebar
- **Interval**: Slider from 1-30 seconds
- **Behavior**: Page automatically reloads data at interval
- **Visual**: Progress indicator during reload

### Chart Interactions
- **Hover**: Shows detailed tooltip with exact values
- **Zoom**: Click and drag to zoom into time range
- **Pan**: Shift + drag to pan across timeline
- **Download**: Camera icon to export PNG

### Table Features
- **Sortable**: Click column headers to sort
- **Scrollable**: Fixed header with scrolling rows
- **Color-coded**: Background color indicates threat level
- **Full-width**: Expands to use available space

---

## Responsive Design

The dashboard is fully responsive:
- **Large Screens (>1920px)**: Full layout with wide charts
- **Medium Screens (1024-1920px)**: Standard layout
- **Small Screens (<1024px)**: Stacked layout, sidebar collapses

---

## Visual Enhancements

### Glassmorphism Effects
- Subtle backdrop blur on metric cards
- Semi-transparent backgrounds
- Soft shadows for depth

### Neon Glow Effects
- Headers have cyan text shadow
- Threat level indicator glows with threat color
- Anomaly markers pulse subtly on chart

### Micro-Animations
- Metric values count up on load
- Chart lines animate in from left
- Table rows fade in sequentially
- Hover effects on interactive elements

---

## Accessibility

- **High Contrast**: All text meets WCAG AA standards
- **Color Blindness**: Colors are distinguishable by shape/pattern
- **Keyboard Navigation**: Full keyboard support
- **Screen Readers**: Semantic HTML with ARIA labels

---

## Performance Optimizations

- **Lazy Loading**: Data fetched only when needed
- **Caching**: Database queries cached for 1 second
- **Efficient Queries**: Indexed database columns
- **Limited Results**: Charts show max 100 points
- **Debouncing**: Auto-refresh prevents query spam

---

## Example Data View

When running with test data, you'll see:

**Metrics:**
- Total Packets: ~2,700 (from 50 flows)
- Anomalies: ~7-8 (15% rate)
- Threat Level: Varies based on most recent

**Chart:**
- Blue bars showing varied packet counts (10-200 packets/flow)
- Red line fluctuating between 0.0-1.0
- Red markers on anomalies (score > 0.6)

**Table:**
- 7-8 rows of anomalies
- Mix of HIGH/MEDIUM threat levels
- Various protocols (TCP, UDP, ICMP)
- Realistic IP addresses and ports

**Logs:**
- "Test data generation started"
- "Generated 50 flows"
- "Detected 8 anomalies"
- "Test data generation completed"

---

## Browser Compatibility

Tested and working on:
- ✅ Chrome/Edge (Latest)
- ✅ Firefox (Latest)
- ✅ Safari (Latest)
- ✅ Mobile browsers (iOS Safari, Chrome Mobile)

---

## Screenshot Checklist

If taking screenshots for documentation:

1. **Generate diverse test data**:
   ```bash
   python generate_test_data.py 100 0.2
   ```

2. **Set auto-refresh to 5 seconds**

3. **Capture full browser window** (not just dashboard)

4. **Show multiple anomalies** in table

5. **Ensure chart shows varied data** (not flat line)

6. **Include sidebar** in frame

7. **Use light/dark mode** as appropriate

---

**The dashboard provides a beautiful, functional interface for real-time network security monitoring!**
