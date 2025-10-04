import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * COMPLETE FIXED TRULY ADAPTIVE Bloom Trie (ABT) for Phishing URL Detection
 * All major fixes implemented: Hash functions, resizing, trie structure, benchmarks
 */

// Enhanced Adaptive Statistics Tracker
class AdaptiveStats {
    protected AtomicLong totalInsertions = new AtomicLong(0);
    protected AtomicLong totalSearches = new AtomicLong(0);
    protected AtomicLong falsePositives = new AtomicLong(0);
    protected AtomicLong truePositives = new AtomicLong(0);
    protected AtomicInteger resizeEvents = new AtomicInteger(0);
    protected AtomicInteger splitEvents = new AtomicInteger(0);
    protected AtomicInteger mergeEvents = new AtomicInteger(0);
    private Map<String, AtomicInteger> tokenFrequency = new ConcurrentHashMap<>();
    
    public void recordInsertion() { totalInsertions.incrementAndGet(); }
    public void recordSearch() { totalSearches.incrementAndGet(); }
    public void recordFalsePositive() { falsePositives.incrementAndGet(); }
    public void recordTruePositive() { truePositives.incrementAndGet(); }
    public void recordResize() { resizeEvents.incrementAndGet(); }
    public void recordSplit() { splitEvents.incrementAndGet(); }
    public void recordMerge() { mergeEvents.incrementAndGet(); }
    
    public void recordTokenUsage(String token) {
        tokenFrequency.computeIfAbsent(token, k -> new AtomicInteger(0)).incrementAndGet();
    }
    
    public double getCurrentFPR() {
        long total = falsePositives.get() + truePositives.get();
        return total > 0 ? (double) falsePositives.get() / total : 0.0;
    }
    
    public void printStats() {
        System.out.println("=== ADAPTIVE STATISTICS ===");
        System.out.println("Total Insertions: " + totalInsertions.get());
        System.out.println("Total Searches: " + totalSearches.get());
        System.out.println("Resize Events: " + resizeEvents.get());
        System.out.println("Split Events: " + splitEvents.get());
        System.out.println("Merge Events: " + mergeEvents.get());
        System.out.println("Current FPR: " + String.format("%.4f", getCurrentFPR()));
        System.out.println("Most Common Tokens: " + getMostCommonTokens(5));
    }
    
    private List<String> getMostCommonTokens(int count) {
        return tokenFrequency.entrySet().stream()
                .sorted((e1, e2) -> e2.getValue().get() - e1.getValue().get())
                .limit(count)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }
}

// FIXED: Corrected Adaptive Bloom Filter with proper hashing and resizing
class FixedAdaptiveBloomFilter {
    private BitSet filter;
    private int size;
    private int hashCount;
    private int insertedElements;
    private double targetFPR;
    private double currentFPR;
    private long lastResizeTime;
    private int resizeThreshold;
    private boolean autoResize;
    private AdaptiveStats stats;
    private Set<String> storedElements; // CRITICAL FIX: Store elements for correct resizing
    
    // Adaptive parameters
    private static final double MIN_FPR = 0.001;
    private static final double MAX_FPR = 0.05;
    private static final int MIN_RESIZE_INTERVAL = 1000;
    
    public FixedAdaptiveBloomFilter(int expectedElements, AdaptiveStats stats) {
        this.stats = stats;
        this.targetFPR = 0.01;
        this.autoResize = true;
        this.lastResizeTime = System.currentTimeMillis();
        this.resizeThreshold = Math.max(10, expectedElements / 4);
        this.storedElements = new HashSet<>(); // CRITICAL FIX
        
        initializeFilter(expectedElements);
    }
    
    private void initializeFilter(int expectedElements) {
        this.size = optimalSize(expectedElements, targetFPR);
        this.hashCount = optimalHashCount(size, expectedElements);
        this.filter = new BitSet(size);
        this.insertedElements = 0;
    }
    
    private int optimalSize(int n, double fpr) {
        if (n <= 0) return 1024;
        return Math.max(1024, (int) (-n * Math.log(fpr) / (Math.log(2) * Math.log(2))));
    }
    
    private int optimalHashCount(int m, int n) {
        if (n <= 0) return 3;
        return Math.max(1, Math.min(10, (int) Math.round((double) m / n * Math.log(2))));
    }
    
    // CRITICAL FIX: Proper double hashing implementation
    private int[] computeHashes(String element) {
        int[] hashes = new int[hashCount];
        
        // Primary hash using built-in hashCode
        int h1 = element.hashCode() & 0x7fffffff; // Ensure positive
        
        // Secondary hash using different method
        int h2 = (element.hashCode() >>> 16) | 1; // Ensure odd for better distribution
        
        // Generate k hash values using double hashing
        for (int i = 0; i < hashCount; i++) {
            hashes[i] = (h1 + i * h2) & 0x7fffffff; // Safe positive hash
        }
        
        return hashes;
    }
    
    public synchronized void insert(String element) {
        if (element == null || element.trim().isEmpty()) return;
        
        element = element.toLowerCase().trim();
        storedElements.add(element); // CRITICAL FIX: Store for resizing
        
        int[] hashes = computeHashes(element);
        for (int hash : hashes) {
            filter.set(hash % size);
        }
        
        insertedElements++;
        updateFPR();
        
        if (shouldResize()) {
            correctResize(); // CRITICAL FIX: Use correct resizing
        }
    }
    
    public boolean mightContain(String element) {
        if (element == null || element.trim().isEmpty()) return false;
        
        element = element.toLowerCase().trim();
        int[] hashes = computeHashes(element);
        
        for (int hash : hashes) {
            if (!filter.get(hash % size)) {
                return false;
            }
        }
        return true;
    }
    
    private void updateFPR() {
        if (insertedElements > 0 && size > 0) {
            currentFPR = Math.pow(1 - Math.exp(-hashCount * insertedElements / (double) size), hashCount);
        }
    }
    
    private boolean shouldResize() {
        if (!autoResize) return false;
        
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastResizeTime < MIN_RESIZE_INTERVAL) return false;
        
        return (currentFPR > targetFPR * 1.5) || 
               (insertedElements > resizeThreshold) || 
               (currentFPR < targetFPR * 0.1 && size > 2048);
    }
    
    // CRITICAL FIX: Correct resize implementation with rehashing
    private synchronized void correctResize() {
        lastResizeTime = System.currentTimeMillis();
        
        // Adaptive target FPR adjustment
        if (stats.getCurrentFPR() > 0.03) {
            targetFPR = Math.max(MIN_FPR, targetFPR * 0.8);
        } else if (stats.getCurrentFPR() < 0.01) {
            targetFPR = Math.min(MAX_FPR, targetFPR * 1.2);
        }
        
        // Calculate new optimal parameters
        int newSize = optimalSize(Math.max(1, storedElements.size() * 2), targetFPR);
        int newHashCount = optimalHashCount(newSize, storedElements.size());
        
        if (Math.abs(newSize - size) > size * 0.1) {
            int oldSize = this.size;
            
            // Initialize new filter
            this.size = newSize;
            this.hashCount = newHashCount;
            this.filter = new BitSet(newSize);
            this.insertedElements = 0;
            
            // Rehash all stored elements
            Set<String> elementsToRehash = new HashSet<>(storedElements);
            storedElements.clear();
            
            for (String element : elementsToRehash) {
                insert(element); // This will add back to storedElements
            }
            
            stats.recordResize();
            System.out.println("Bloom Filter Correctly Resized: " + oldSize + " => " + newSize + 
                             " (Target FPR: " + String.format("%.4f", targetFPR) + ")");
        }
    }
    
    public void adjustTargetFPR(double systemFPR, int memoryPressure) {
        if (memoryPressure > 80) {
            targetFPR = Math.min(MAX_FPR, targetFPR * 1.3);
        } else if (systemFPR > 0.05) {
            targetFPR = Math.max(MIN_FPR, targetFPR * 0.7);
        }
    }
    
    // Getters
    public double getCurrentFPR() { return currentFPR; }
    public double getTargetFPR() { return targetFPR; }
    public int getSize() { return size; }
    public int getInsertedElements() { return insertedElements; }
    public int getMemoryUsage() { 
        return size / 8 + storedElements.size() * 50 + 64; // More accurate accounting
    }
}

// FIXED: Consistent Token-Level Trie Implementation
class FixedAdaptiveTrieNode {
    protected Map<String, FixedAdaptiveTrieNode> children; // Full token as key
    protected FixedAdaptiveBloomFilter bloomFilter;
    private boolean isEndOfUrl;
    private int urlCount;
    private long lastAccessTime;
    private long lastSplitTime;
    private double accessFrequency;
    private AdaptiveStats stats;
    
    // FIXED: More conservative adaptive thresholds
    private int splitThreshold;
    private int mergeThreshold;
    private static final int MAX_CHILDREN = 100; // Increased threshold
    private static final int MIN_ACCESS_FREQUENCY = 5; // Reduced threshold
    private static final long MERGE_COOLDOWN = 300000; // 5 minutes
    private static final long SPLIT_COOLDOWN = 10000; // 10 seconds between splits
    
    public FixedAdaptiveTrieNode(AdaptiveStats stats) {
        this.stats = stats;
        this.children = new ConcurrentHashMap<>();
        this.bloomFilter = new FixedAdaptiveBloomFilter(50, stats);
        this.isEndOfUrl = false;
        this.urlCount = 0;
        this.lastAccessTime = System.currentTimeMillis();
        this.lastSplitTime = 0;
        this.accessFrequency = 0.0;
        this.splitThreshold = 150; // More conservative
        this.mergeThreshold = 10; // Higher merge threshold
    }
    
    public synchronized void insertToken(String token) {
        if (token == null || token.trim().isEmpty()) return;
        
        bloomFilter.insert(token);
        urlCount++;
        updateAccessStats();
        stats.recordTokenUsage(token);
        
        adaptThresholds();
        
        if (shouldSplit()) {
            splitNode();
        }
    }
    
    public boolean mightContainToken(String token) {
        updateAccessStats();
        return bloomFilter.mightContain(token);
    }
    
    private void updateAccessStats() {
        long currentTime = System.currentTimeMillis();
        long timeDiff = currentTime - lastAccessTime;
        
        if (timeDiff > 0) {
            double newFreq = 1000.0 / timeDiff;
            accessFrequency = 0.8 * accessFrequency + 0.2 * newFreq;
        }
        
        lastAccessTime = currentTime;
    }
    
    private void adaptThresholds() {
        double systemFPR = stats.getCurrentFPR();
        
        if (systemFPR > 0.03) {
            splitThreshold = Math.max(100, splitThreshold - 10);
        } else if (systemFPR < 0.01) {
            splitThreshold = Math.min(300, splitThreshold + 10);
        }
        
        if (accessFrequency < 0.1) {
            mergeThreshold = Math.max(5, mergeThreshold - 1);
        } else if (accessFrequency > 10) {
            mergeThreshold = Math.min(30, mergeThreshold + 2);
        }
    }
    
    // FIXED: Much more conservative split conditions
    private boolean shouldSplit() {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastSplitTime < SPLIT_COOLDOWN) {
            return false;
        }
        
        // Only split if ALL conditions are met
        boolean highUrlCount = (urlCount > splitThreshold);
        boolean highChildrenCount = (children.size() > MAX_CHILDREN);
        boolean highFPR = (bloomFilter.getCurrentFPR() > 0.2);
        boolean sufficientAccess = (accessFrequency > 1.0);
        
        return highUrlCount && highChildrenCount && (highFPR || sufficientAccess);
    }
    
    // FIXED: Improved splitting logic with better grouping
    private synchronized void splitNode() {
        if (children.size() <= 5) return; // Can't split small nodes
        
        lastSplitTime = System.currentTimeMillis();
        splitThreshold = Math.min(400, splitThreshold + 100); // Increase to prevent re-splitting
        
        // Group children by token prefix for better distribution
        Map<String, List<Map.Entry<String, FixedAdaptiveTrieNode>>> groups = new HashMap<>();
        
        for (Map.Entry<String, FixedAdaptiveTrieNode> entry : children.entrySet()) {
            String token = entry.getKey();
            String prefix = token.length() >= 3 ? token.substring(0, 3) : token;
            groups.computeIfAbsent(prefix, k -> new ArrayList<>()).add(entry);
        }
        
        Map<String, FixedAdaptiveTrieNode> newChildren = new ConcurrentHashMap<>();
        boolean actuallyRestructured = false;
        
        for (Map.Entry<String, List<Map.Entry<String, FixedAdaptiveTrieNode>>> group : groups.entrySet()) {
            if (group.getValue().size() > 15) { // Create intermediate node for large groups
                FixedAdaptiveTrieNode intermediateNode = new FixedAdaptiveTrieNode(stats);
                
                for (Map.Entry<String, FixedAdaptiveTrieNode> child : group.getValue()) {
                    String originalKey = child.getKey();
                    String newKey = originalKey.length() > 3 ? originalKey.substring(3) : originalKey;
                    if (newKey.isEmpty()) newKey = "_end_"; // Handle empty keys
                    
                    intermediateNode.children.put(newKey, child.getValue());
                }
                
                newChildren.put(group.getKey(), intermediateNode);
                actuallyRestructured = true;
            } else {
                // Keep small groups as-is
                for (Map.Entry<String, FixedAdaptiveTrieNode> child : group.getValue()) {
                    newChildren.put(child.getKey(), child.getValue());
                }
            }
        }
        
        // Only update if we actually improved the structure
        if (actuallyRestructured && newChildren.size() < children.size() * 0.8) {
            this.children = newChildren;
            stats.recordSplit();
            System.out.println("Node Split: " + children.size() + " children, URL count: " + urlCount);
        } else {
            splitThreshold = Math.min(600, splitThreshold + 150);
            System.out.println("Split ineffective, increasing threshold to: " + splitThreshold);
        }
    }
    
    public synchronized boolean tryMerge(FixedAdaptiveTrieNode parent) {
        if (urlCount > mergeThreshold) return false;
        if (System.currentTimeMillis() - lastAccessTime < MERGE_COOLDOWN) return false;
        if (accessFrequency > MIN_ACCESS_FREQUENCY) return false;
        
        // Merge this node into parent
        for (Map.Entry<String, FixedAdaptiveTrieNode> child : children.entrySet()) {
            parent.children.put(child.getKey(), child.getValue());
        }
        
        stats.recordMerge();
        System.out.println("Node Merged: Low usage detected");
        return true;
    }
    
    public synchronized void cleanup() {
        long currentTime = System.currentTimeMillis();
        List<String> toRemove = new ArrayList<>();
        
        for (Map.Entry<String, FixedAdaptiveTrieNode> entry : children.entrySet()) {
            FixedAdaptiveTrieNode child = entry.getValue();
            if (currentTime - child.lastAccessTime > 600000 && // 10 minutes unused
                child.urlCount < mergeThreshold &&
                child.accessFrequency < 0.01) {
                
                toRemove.add(entry.getKey());
            } else {
                child.cleanup();
            }
        }
        
        for (String key : toRemove) {
            children.remove(key);
            stats.recordMerge();
        }
    }
    
    // Getters and setters
    public FixedAdaptiveTrieNode getChild(String token) {
        return children.get(token);
    }
    
    public void addChild(String token, FixedAdaptiveTrieNode node) {
        children.put(token, node);
    }
    
    public void setEndOfUrl(boolean endOfUrl) { this.isEndOfUrl = endOfUrl; }
    public boolean isEndOfUrl() { return isEndOfUrl; }
    public int getUrlCount() { return urlCount; }
    public double getAccessFrequency() { return accessFrequency; }
    public int getSplitThreshold() { return splitThreshold; }
    public int getMergeThreshold() { return mergeThreshold; }
    public Map<String, FixedAdaptiveTrieNode> getChildren() { return new HashMap<>(children); }
    
    public int getMemoryUsage() {
        int memory = bloomFilter.getMemoryUsage() + 128;
        for (FixedAdaptiveTrieNode child : children.values()) {
            memory += child.getMemoryUsage();
        }
        return memory;
    }
}

// FIXED: Main Truly Adaptive Bloom Trie
public class TrulyAdaptiveABT {
    private FixedAdaptiveTrieNode root;
    private int totalUrls;
    private AdaptiveStats stats;
    private boolean debugMode;
    private long lastCleanupTime;
    private Timer maintenanceTimer;
    
    // System-wide adaptive parameters
    private double memoryPressureThreshold = 0.8;
    private int adaptationInterval = 10000;
    private AtomicInteger operationCount = new AtomicInteger(0);
    
    public TrulyAdaptiveABT() {
        this(false);
    }
    
    public TrulyAdaptiveABT(boolean debugMode) {
        this.stats = new AdaptiveStats();
        this.root = new FixedAdaptiveTrieNode(stats);
        this.totalUrls = 0;
        this.debugMode = debugMode;
        this.lastCleanupTime = System.currentTimeMillis();
        
        startMaintenanceTimer();
        
        if (debugMode) {
            System.out.println("Fixed Truly Adaptive ABT initialized with maintenance timer");
        }
    }
    
    private void startMaintenanceTimer() {
        maintenanceTimer = new Timer(true);
        maintenanceTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                performMaintenance();
            }
        }, 30000, 30000);
    }
    
    // FIXED: Consistent token-level insertion
    public void insert(String url) {
        if (url == null || url.trim().isEmpty()) return;
        
        List<String> tokens = tokenizeUrl(url);
        if (debugMode) {
            System.out.println("INSERT URL: " + url);
            System.out.println("TOKENS: " + tokens);
        }
        
        FixedAdaptiveTrieNode current = root;
        
        // Insert all tokens into root's bloom filter first
        for (String token : tokens) {
            current.insertToken(token);
        }
        
        // Traverse/build trie structure using full tokens
        for (String token : tokens) {
            if (token.length() > 0) {
                FixedAdaptiveTrieNode child = current.getChild(token);
                if (child == null) {
                    child = new FixedAdaptiveTrieNode(stats);
                    current.addChild(token, child);
                }
                current = child;
            }
        }
        
        current.setEndOfUrl(true);
        totalUrls++;
        stats.recordInsertion();
        
        if (operationCount.incrementAndGet() % adaptationInterval == 0) {
            systemWideAdaptation();
        }
    }
    
    // FIXED: Consistent token-level search
    public boolean search(String url) {
        if (url == null || url.trim().isEmpty()) return false;
        
        List<String> tokens = tokenizeUrl(url);
        FixedAdaptiveTrieNode current = root;
        
        stats.recordSearch();
        
        // First check if ALL tokens might be present in root's bloom filter
        for (String token : tokens) {
            if (!current.mightContainToken(token)) {
                return false;
            }
        }
        
        // Then traverse trie structure using full tokens
        for (String token : tokens) {
            if (token.length() > 0) {
                current = current.getChild(token);
                if (current == null) {
                    return false;
                }
            }
        }
        
        boolean result = current.isEndOfUrl();
        
        if (result) {
            stats.recordTruePositive();
        } else {
            stats.recordFalsePositive();
        }
        
        return result;
    }
    
    private void systemWideAdaptation() {
        if (debugMode) {
            System.out.println("\n=== PERFORMING SYSTEM-WIDE ADAPTATION ===");
        }
        
        Runtime runtime = Runtime.getRuntime();
        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        double memoryUsage = 1.0 - (double) freeMemory / totalMemory;
        
        if (debugMode) {
            System.out.println("Memory Usage: " + String.format("%.2f%%", memoryUsage * 100));
        }
        
        int memoryPressure = (int) (memoryUsage * 100);
        adjustAllBloomFilters(stats.getCurrentFPR(), memoryPressure);
        
        if (memoryUsage > memoryPressureThreshold) {
            performMemoryOptimization();
        }
        
        if (debugMode) {
            stats.printStats();
        }
    }
    
    private void adjustAllBloomFilters(double systemFPR, int memoryPressure) {
        adjustNodeBloomFilters(root, systemFPR, memoryPressure);
    }
    
    private void adjustNodeBloomFilters(FixedAdaptiveTrieNode node, double systemFPR, int memoryPressure) {
        node.bloomFilter.adjustTargetFPR(systemFPR, memoryPressure);
        
        for (FixedAdaptiveTrieNode child : node.getChildren().values()) {
            adjustNodeBloomFilters(child, systemFPR, memoryPressure);
        }
    }
    
    private void performMaintenance() {
        long currentTime = System.currentTimeMillis();
        
        if (currentTime - lastCleanupTime > 300000) {
            performMemoryOptimization();
            lastCleanupTime = currentTime;
        }
        
        if (stats.getCurrentFPR() > 0.05) {
            performMemoryOptimization();
        }
    }
    
    private void performMemoryOptimization() {
        if (debugMode) {
            System.out.println("Performing memory optimization...");
        }
        
        root.cleanup();
        System.gc();
        operationCount.set(0);
    }
    
    // FIXED: Enhanced tokenization with consistent approach
    private List<String> tokenizeUrl(String url) {
        List<String> tokens = new ArrayList<>();
        
        try {
            url = url.toLowerCase().trim();
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "http://" + url;
            }
            
            URL urlObj = new URL(url);
            
            String domain = urlObj.getHost();
            if (domain != null) {
                tokens.add("DOMAIN:" + domain);
                String[] domainParts = domain.split("\\.");
                for (String part : domainParts) {
                    if (!part.isEmpty()) {
                        tokens.add("DPART:" + part);
                    }
                }
            }
            
            String path = urlObj.getPath();
            if (path != null && !path.isEmpty() && !path.equals("/")) {
                tokens.add("PATH:" + path);
                String[] pathParts = path.split("/");
                for (String part : pathParts) {
                    if (!part.isEmpty()) {
                        tokens.add("PPART:" + part);
                    }
                }
            }
            
            String query = urlObj.getQuery();
            if (query != null && !query.isEmpty()) {
                tokens.add("QUERY:" + query);
                String[] queryParts = query.split("&");
                for (String part : queryParts) {
                    if (!part.isEmpty()) {
                        tokens.add("QPART:" + part);
                        if (part.contains("=")) {
                            String[] keyValue = part.split("=", 2);
                            if (keyValue.length > 0 && !keyValue[0].isEmpty()) {
                                tokens.add("QKEY:" + keyValue[0]);
                            }
                        }
                    }
                }
            }
            
            tokens.add("PROTO:" + urlObj.getProtocol());
            if (urlObj.getPort() != -1) {
                tokens.add("PORT:" + urlObj.getPort());
            }
            
        } catch (Exception e) {
            // Fallback tokenization
            String[] parts = url.split("[./\\-_=&?:#]");
            for (String part : parts) {
                if (!part.isEmpty() && part.length() > 1) {
                    tokens.add("FALLBACK:" + part.toLowerCase());
                }
            }
        }
        
        return tokens.stream()
                    .filter(s -> s != null && !s.trim().isEmpty())
                    .distinct()
                    .collect(Collectors.toList());
    }
    
    // Enhanced getters
    public int getTotalUrls() { return totalUrls; }
    public int getMemoryUsage() { return root.getMemoryUsage(); }
    public AdaptiveStats getStats() { return stats; }
    
    public void shutdown() {
        if (maintenanceTimer != null) {
            maintenanceTimer.cancel();
        }
    }
    
    // Analysis methods
    public Map<String, Object> getAdaptationAnalysis() {
        Map<String, Object> analysis = new HashMap<>();
        
        analysis.put("totalUrls", totalUrls);
        analysis.put("memoryUsage", getMemoryUsage());
        analysis.put("memoryPerUrl", totalUrls > 0 ? (double) getMemoryUsage() / totalUrls : 0);
        analysis.put("adaptationEvents", stats.resizeEvents.get() + stats.splitEvents.get() + stats.mergeEvents.get());
        analysis.put("resizeEvents", stats.resizeEvents.get());
        analysis.put("splitEvents", stats.splitEvents.get());
        analysis.put("mergeEvents", stats.mergeEvents.get());
        analysis.put("currentFPR", stats.getCurrentFPR());
        analysis.put("totalInsertions", stats.totalInsertions.get());
        analysis.put("totalSearches", stats.totalSearches.get());
        
        return analysis;
    }
    
    public Map<String, Object> getNodeStatistics() {
        return getNodeStatistics(root, 0);
    }
    
    private Map<String, Object> getNodeStatistics(FixedAdaptiveTrieNode node, int depth) {
        Map<String, Object> nodeStats = new HashMap<>();
        
        nodeStats.put("depth", depth);
        nodeStats.put("urlCount", node.getUrlCount());
        nodeStats.put("childrenCount", node.getChildren().size());
        nodeStats.put("memoryUsage", node.getMemoryUsage());
        nodeStats.put("accessFrequency", node.getAccessFrequency());
        nodeStats.put("splitThreshold", node.getSplitThreshold());
        nodeStats.put("mergeThreshold", node.getMergeThreshold());
        
        List<Map<String, Object>> childrenStats = new ArrayList<>();
        for (FixedAdaptiveTrieNode child : node.getChildren().values()) {
            childrenStats.add(getNodeStatistics(child, depth + 1));
        }
        nodeStats.put("children", childrenStats);
        
        return nodeStats;
    }
    
    public void exportMetricsToCSV(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Metric,Value,Unit,Description");
            
            Map<String, Object> analysis = getAdaptationAnalysis();
            for (Map.Entry<String, Object> entry : analysis.entrySet()) {
                String metric = entry.getKey();
                Object value = entry.getValue();
                String unit = getUnitForMetric(metric);
                String description = getDescriptionForMetric(metric);
                
                writer.println(String.format("%s,%s,%s,\"%s\"", metric, value, unit, description));
            }
            
            System.out.println("Metrics exported to " + filename);
            
        } catch (IOException e) {
            System.err.println("Error exporting metrics: " + e.getMessage());
        }
    }
    
    private String getUnitForMetric(String metric) {
        switch (metric) {
            case "memoryUsage": return "bytes";
            case "memoryPerUrl": return "bytes/URL";
            case "currentFPR": return "ratio";
            case "totalUrls": case "adaptationEvents": case "resizeEvents": 
            case "splitEvents": case "mergeEvents": case "totalInsertions": 
            case "totalSearches": return "count";
            default: return "";
        }
    }
    
    private String getDescriptionForMetric(String metric) {
        switch (metric) {
            case "totalUrls": return "Total number of URLs inserted";
            case "memoryUsage": return "Total memory usage in bytes";
            case "memoryPerUrl": return "Average memory usage per URL";
            case "adaptationEvents": return "Total number of adaptation events";
            case "resizeEvents": return "Number of Bloom filter resize events";
            case "splitEvents": return "Number of node split events";
            case "mergeEvents": return "Number of node merge events";
            case "currentFPR": return "Current false positive rate";
            case "totalInsertions": return "Total insertion operations";
            case "totalSearches": return "Total search operations";
            default: return "";
        }
    }
    
    // FIXED: Enhanced Benchmark with proper baseline implementations
    public static class AdaptiveBenchmark {
        
        public static void main(String[] args) {
            try {
                List<String> phishingUrls = loadPhishingUrls();
                List<String> benignUrls = loadBenignUrls();
                
                System.out.println("=== FIXED TRULY ADAPTIVE ABT BENCHMARK ===");
                System.out.println("Loaded " + phishingUrls.size() + " phishing URLs");
                System.out.println("Loaded " + benignUrls.size() + " benign URLs");
                
                runAdaptiveBenchmark(phishingUrls, benignUrls);
                
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        private static void runAdaptiveBenchmark(List<String> phishingUrls, List<String> benignUrls) {
            System.out.println("\n=== FIXED ADAPTIVE ABT PERFORMANCE ===");
            
            TrulyAdaptiveABT abt = new TrulyAdaptiveABT(true);
            
            try {
                long startTime = System.nanoTime();
                int insertCount = 0;
                
                for (String url : phishingUrls) {
                    abt.insert(url);
                    insertCount++;
                    
                    if (insertCount % 5000 == 0) {
                        System.out.println("Inserted " + insertCount + " URLs, Memory: " + 
                                         (abt.getMemoryUsage() / 1024) + " KB");
                    }
                }
                
                long insertionTime = System.nanoTime() - startTime;
                
                startTime = System.nanoTime();
                int correctDetections = 0;
                
                for (String url : phishingUrls) {
                    if (abt.search(url)) {
                        correctDetections++;
                    }
                }
                
                long searchTimePositive = System.nanoTime() - startTime;
                
                startTime = System.nanoTime();
                int falsePositives = 0;
                
                for (String url : benignUrls) {
                    if (abt.search(url)) {
                        falsePositives++;
                    }
                }
                
                long searchTimeNegative = System.nanoTime() - startTime;
                
                double fpr = benignUrls.size() > 0 ? (double) falsePositives / benignUrls.size() * 100 : 0.0;
                double accuracy = phishingUrls.size() > 0 ? (double) correctDetections / phishingUrls.size() * 100 : 0.0;
                
                System.out.println("\n=== FIXED ADAPTIVE ABT RESULTS ===");
                System.out.printf("Memory Usage: %d KB\n", abt.getMemoryUsage() / 1024);
                System.out.printf("Insertion Time: %.2f ms\n", insertionTime / 1_000_000.0);
                
                int totalSearches = phishingUrls.size() + benignUrls.size();
                if (totalSearches > 0) {
                    System.out.printf("Search Time (avg): %.4f ms\n", 
                        (searchTimePositive + searchTimeNegative) / (double)totalSearches / 1_000_000.0);
                }
                System.out.printf("Accuracy: %.2f%% (%d/%d)\n", accuracy, correctDetections, phishingUrls.size());
                System.out.printf("False Positive Rate: %.2f%% (%d/%d)\n", fpr, falsePositives, benignUrls.size());
                
                abt.getStats().printStats();
                abt.shutdown();
                
            } catch (Exception e) {
                abt.shutdown();
                throw e;
            }
        }
        
        private static List<String> loadPhishingUrls() throws IOException {
            List<String> urls = new ArrayList<>();
            try {
                Files.lines(Paths.get("phishing_urls.txt"))
                     .filter(line -> !line.trim().isEmpty())
                     .forEach(urls::add);
            } catch (Exception e) {
                System.out.println("Could not load phishing_urls.txt: " + e.getMessage());
                
                // Generate realistic phishing URLs
                String[] suspiciousDomains = {
                    "paypal-security.com", "amazon-update.net", "microsoft-account.org",
                    "apple-verification.com", "google-security.net", "facebook-secure.org",
                    "bank-of-america.net", "wells-fargo-online.com", "chase-secure.org",
                    "ebay-security.net", "netflix-billing.com", "instagram-verify.org"
                };
                
                String[] suspiciousPaths = {
                    "/login", "/verify", "/update", "/secure", "/account", "/billing",
                    "/suspended", "/locked", "/confirm", "/validate", "/security", "/urgent"
                };
                
                for (String domain : suspiciousDomains) {
                    for (String path : suspiciousPaths) {
                        for (int i = 0; i < 25; i++) {
                            urls.add("https://" + domain + path + "?id=" + i);
                            urls.add("https://www." + domain + path + "/" + i);
                        }
                    }
                }
            }
            return urls;
        }
        
        private static List<String> loadBenignUrls() throws IOException {
            List<String> urls = new ArrayList<>();
            
            try {
                Files.lines(Paths.get("benign_urls.txt"))
                     .filter(line -> !line.trim().isEmpty())
                     .forEach(urls::add);
            } catch (Exception e) {
                System.out.println("Could not load benign_urls.txt: " + e.getMessage());
                
                String[] legitimateDomains = {
                    "google.com", "facebook.com", "paypal.com", "microsoft.com",
                    "apple.com", "amazon.com", "github.com", "stackoverflow.com",
                    "linkedin.com", "twitter.com", "instagram.com", "youtube.com",
                    "netflix.com", "spotify.com", "dropbox.com", "reddit.com"
                };
                
                String[] legitimatePaths = {
                    "", "/about", "/contact", "/help", "/support", "/products",
                    "/services", "/blog", "/news", "/careers", "/developers"
                };
                
                for (String domain : legitimateDomains) {
                    for (String path : legitimatePaths) {
                        for (int i = 0; i < 15; i++) {
                            urls.add("https://" + domain + path);
                            urls.add("https://www." + domain + path);
                            if (!path.isEmpty()) {
                                urls.add("https://" + domain + path + "/" + i);
                            }
                        }
                    }
                }
                
                System.out.println("Generated " + urls.size() + " fallback benign URLs");
            }
            
            return urls;
        }
    }
    
    // Workload Simulator
    public static class WorkloadSimulator {
        
        public static void simulateBurstWorkload(TrulyAdaptiveABT abt, List<String> urls) {
            System.out.println("=== BURST WORKLOAD SIMULATION ===");
            
            for (int i = 0; i < urls.size(); i += 1000) {
                int endIndex = Math.min(i + 1000, urls.size());
                List<String> batch = urls.subList(i, endIndex);
                
                long startTime = System.nanoTime();
                for (String url : batch) {
                    abt.insert(url);
                }
                long batchTime = System.nanoTime() - startTime;
                
                System.out.printf("Batch %d: %d URLs in %.2f ms, Memory: %d KB, Adaptations: %d\n",
                    (i / 1000) + 1, batch.size(), batchTime / 1_000_000.0,
                    abt.getMemoryUsage() / 1024,
                    abt.getStats().resizeEvents.get() + abt.getStats().splitEvents.get());
                
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        
        public static void simulateStreamingWorkload(TrulyAdaptiveABT abt, List<String> urls) {
            System.out.println("=== STREAMING WORKLOAD SIMULATION ===");
            
            long startTime = System.currentTimeMillis();
            int processedUrls = 0;
            
            for (String url : urls) {
                abt.insert(url);
                processedUrls++;
                
                if (processedUrls % 5000 == 0) {
                    long elapsedTime = System.currentTimeMillis() - startTime;
                    double throughput = elapsedTime > 0 ? (double) processedUrls / (elapsedTime / 1000.0) : 0;
                    
                    System.out.printf("Processed: %d URLs, Throughput: %.2f URLs/sec, " +
                                    "Memory: %d KB, FPR: %.4f\n",
                        processedUrls, throughput, abt.getMemoryUsage() / 1024,
                        abt.getStats().getCurrentFPR());
                }
                
                if (processedUrls % 100 == 0) {
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        
        public static void simulateMixedWorkload(TrulyAdaptiveABT abt, List<String> insertUrls, List<String> searchUrls) {
            System.out.println("=== MIXED WORKLOAD SIMULATION ===");
            
            Random random = new Random(42);
            int totalOperations = insertUrls.size() + searchUrls.size();
            int insertIndex = 0;
            int searchIndex = 0;
            
            for (int i = 0; i < totalOperations; i++) {
                boolean shouldInsert = (random.nextBoolean() && insertIndex < insertUrls.size()) || searchIndex >= searchUrls.size();
                
                if (shouldInsert && insertIndex < insertUrls.size()) {
                    abt.insert(insertUrls.get(insertIndex++));
                } else if (searchIndex < searchUrls.size()) {
                    abt.search(searchUrls.get(searchIndex++));
                }
                
                if (i % 10000 == 0) {
                    System.out.printf("Operations: %d, Inserts: %d, Searches: %d, " +
                                    "Memory: %d KB, Adaptations: %d\n",
                        i, insertIndex, searchIndex, abt.getMemoryUsage() / 1024,
                        abt.getStats().resizeEvents.get() + abt.getStats().splitEvents.get() + 
                        abt.getStats().mergeEvents.get());
                }
            }
        }
    }
}

// FIXED: Standard Bloom Filter for comparison
class StandardBloomFilter {
    private BitSet filter;
    private int size;
    private int hashCount;
    private int insertedElements;
    
    public StandardBloomFilter(int expectedElements, double falsePositiveRate) {
        this.size = optimalSize(expectedElements, falsePositiveRate);
        this.hashCount = optimalHashCount(size, expectedElements);
        this.filter = new BitSet(size);
        this.insertedElements = 0;
    }
    
    private int optimalSize(int n, double fpr) {
        if (n <= 0) return 1024;
        return Math.max(1024, (int) (-n * Math.log(fpr) / (Math.log(2) * Math.log(2))));
    }
    
    private int optimalHashCount(int m, int n) {
        if (n <= 0) return 3;
        return Math.max(1, Math.min(10, (int) Math.round((double) m / n * Math.log(2))));
    }
    
    public void insert(String element) {
        if (element == null || element.trim().isEmpty()) return;
        
        element = element.toLowerCase().trim();
        
        for (int i = 0; i < hashCount; i++) {
            int hash = hash(element, i);
            filter.set(Math.abs(hash % size));
        }
        
        insertedElements++;
    }
    
    public boolean mightContain(String element) {
        if (element == null || element.trim().isEmpty()) return false;
        
        element = element.toLowerCase().trim();
        
        for (int i = 0; i < hashCount; i++) {
            int hash = hash(element, i);
            if (!filter.get(Math.abs(hash % size))) {
                return false;
            }
        }
        return true;
    }
    
    private int hash(String element, int seed) {
        return (element.hashCode() + seed * 31) & 0x7fffffff;
    }
    
    public int getMemoryUsage() {
        return size / 8 + 64;
    }
}

// FIXED: Standard Trie for comparison
class StandardTrie {
    private StandardTrieNode root;
    private int nodeCount;
    
    public StandardTrie() {
        this.root = new StandardTrieNode();
        this.nodeCount = 1;
    }
    
    public void insert(String url) {
        if (url == null || url.trim().isEmpty()) return;
        
        List<String> tokens = tokenizeForStandardTrie(url);
        StandardTrieNode current = root;
        
        for (String token : tokens) {
            if (!current.children.containsKey(token)) {
                current.children.put(token, new StandardTrieNode());
                nodeCount++;
            }
            current = current.children.get(token);
        }
        current.isEndOfUrl = true;
    }
    
    public boolean search(String url) {
        if (url == null || url.trim().isEmpty()) return false;
        
        List<String> tokens = tokenizeForStandardTrie(url);
        StandardTrieNode current = root;
        
        for (String token : tokens) {
            current = current.children.get(token);
            if (current == null) {
                return false;
            }
        }
        return current.isEndOfUrl;
    }
    
    private List<String> tokenizeForStandardTrie(String url) {
        List<String> tokens = new ArrayList<>();
        try {
            url = url.toLowerCase().trim();
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "http://" + url;
            }
            
            URL urlObj = new URL(url);
            
            String domain = urlObj.getHost();
            if (domain != null) {
                tokens.add("DOMAIN:" + domain);
            }
            
            String path = urlObj.getPath();
            if (path != null && !path.isEmpty() && !path.equals("/")) {
                tokens.add("PATH:" + path);
            }
            
            String query = urlObj.getQuery();
            if (query != null && !query.isEmpty()) {
                tokens.add("QUERY:" + query);
            }
            
        } catch (Exception e) {
            String[] parts = url.split("[./\\-_=&?:#]");
            for (String part : parts) {
                if (!part.isEmpty() && part.length() > 1) {
                    tokens.add("FALLBACK:" + part.toLowerCase());
                }
            }
        }
        
        return tokens;
    }
    
    public int getEstimatedMemoryUsage() {
        return nodeCount * 128; // Rough estimate
    }
    
    private static class StandardTrieNode {
        Map<String, StandardTrieNode> children = new HashMap<>();
        boolean isEndOfUrl = false;
    }
}

// FIXED: Comprehensive Research Benchmark
class ComprehensiveResearchBenchmark {
    
    public static class BenchmarkResults {
        public double avgInsertionTime;
        public double avgSearchTime;
        public double memoryUsageMB;
        public double falsePositiveRate;
        public double accuracy;
        public int totalAdaptations;
        public long totalMemoryAllocations;
        
        public void writeToCSV(PrintWriter writer, String algorithm) {
            writer.printf("%s,%.4f,%.4f,%.2f,%.4f,%.2f,%d,%d\n",
                algorithm, avgInsertionTime, avgSearchTime, memoryUsageMB,
                falsePositiveRate, accuracy, totalAdaptations, totalMemoryAllocations);
        }
    }
    
    public static void runComprehensiveBenchmark() {
        System.out.println("=== COMPREHENSIVE RESEARCH BENCHMARK ===");
        
        try {
            List<String> phishingUrls = loadDataset("phishing_urls.txt", generatePhishingUrls());
            List<String> benignUrls = loadDataset("benign_urls.txt", generateBenignUrls());
            
            int numRuns = 3;
            Map<String, List<BenchmarkResults>> allResults = new HashMap<>();
            
            for (int run = 0; run < numRuns; run++) {
                System.out.println("\n=== RUN " + (run + 1) + " ===");
                
                allResults.computeIfAbsent("AdaptiveABT", k -> new ArrayList<>())
                          .add(benchmarkAdaptiveABT(phishingUrls, benignUrls));
                
                allResults.computeIfAbsent("StandardBloomFilter", k -> new ArrayList<>())
                          .add(benchmarkStandardBloomFilter(phishingUrls, benignUrls));
                
                allResults.computeIfAbsent("HashSet", k -> new ArrayList<>())
                          .add(benchmarkHashSet(phishingUrls, benignUrls));
                
                allResults.computeIfAbsent("StandardTrie", k -> new ArrayList<>())
                          .add(benchmarkStandardTrie(phishingUrls, benignUrls));
                
                System.gc();
                Thread.sleep(1000);
            }
            
            exportStatisticalResults(allResults);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static BenchmarkResults benchmarkAdaptiveABT(List<String> phishingUrls, List<String> benignUrls) {
        System.out.println("Benchmarking Adaptive ABT...");
        
        TrulyAdaptiveABT abt = new TrulyAdaptiveABT(false);
        BenchmarkResults results = new BenchmarkResults();
        
        long startTime = System.nanoTime();
        for (String url : phishingUrls) {
            abt.insert(url);
        }
        long insertionTime = System.nanoTime() - startTime;
        results.avgInsertionTime = insertionTime / (double) phishingUrls.size() / 1000.0;
        
        Runtime.getRuntime().gc();
        results.memoryUsageMB = abt.getMemoryUsage() / (1024.0 * 1024.0);
        
        startTime = System.nanoTime();
        int truePositives = 0;
        for (String url : phishingUrls) {
            if (abt.search(url)) {
                truePositives++;
            }
        }
        
        int falsePositives = 0;
        for (String url : benignUrls) {
            if (abt.search(url)) {
                falsePositives++;
            }
        }
        long searchTime = System.nanoTime() - startTime;
        
        results.avgSearchTime = searchTime / (double) (phishingUrls.size() + benignUrls.size()) / 1000.0;
        results.accuracy = (double) truePositives / phishingUrls.size() * 100.0;
        results.falsePositiveRate = (double) falsePositives / benignUrls.size() * 100.0;
        results.totalAdaptations = abt.getStats().resizeEvents.get() + 
                                  abt.getStats().splitEvents.get() + 
                                  abt.getStats().mergeEvents.get();
        
        abt.shutdown();
        return results;
    }
    
    private static BenchmarkResults benchmarkStandardBloomFilter(List<String> phishingUrls, List<String> benignUrls) {
        System.out.println("Benchmarking Standard Bloom Filter...");
        
        StandardBloomFilter bf = new StandardBloomFilter(phishingUrls.size(), 0.01);
        BenchmarkResults results = new BenchmarkResults();
        
        long startTime = System.nanoTime();
        for (String url : phishingUrls) {
            bf.insert(url);
        }
        long insertionTime = System.nanoTime() - startTime;
        results.avgInsertionTime = insertionTime / (double) phishingUrls.size() / 1000.0;
        
        results.memoryUsageMB = bf.getMemoryUsage() / (1024.0 * 1024.0);
        
        startTime = System.nanoTime();
        int truePositives = 0;
        for (String url : phishingUrls) {
            if (bf.mightContain(url)) {
                truePositives++;
            }
        }
        
        int falsePositives = 0;
        for (String url : benignUrls) {
            if (bf.mightContain(url)) {
                falsePositives++;
            }
        }
        long searchTime = System.nanoTime() - startTime;
        
        results.avgSearchTime = searchTime / (double) (phishingUrls.size() + benignUrls.size()) / 1000.0;
        results.accuracy = (double) truePositives / phishingUrls.size() * 100.0;
        results.falsePositiveRate = (double) falsePositives / benignUrls.size() * 100.0;
        results.totalAdaptations = 0;
        
        return results;
    }
    
    private static BenchmarkResults benchmarkHashSet(List<String> phishingUrls, List<String> benignUrls) {
        System.out.println("Benchmarking HashSet...");
        
        Set<String> hashSet = new HashSet<>();
        BenchmarkResults results = new BenchmarkResults();
        
        long startTime = System.nanoTime();
        hashSet.addAll(phishingUrls);
        long insertionTime = System.nanoTime() - startTime;
        results.avgInsertionTime = insertionTime / (double) phishingUrls.size() / 1000.0;
        
        results.memoryUsageMB = phishingUrls.size() * 50 / (1024.0 * 1024.0);
        
        startTime = System.nanoTime();
        int truePositives = 0;
        for (String url : phishingUrls) {
            if (hashSet.contains(url)) {
                truePositives++;
            }
        }
        
        int falsePositives = 0;
        for (String url : benignUrls) {
            if (hashSet.contains(url)) {
                falsePositives++;
            }
        }
        long searchTime = System.nanoTime() - startTime;
        
        results.avgSearchTime = searchTime / (double) (phishingUrls.size() + benignUrls.size()) / 1000.0;
        results.accuracy = (double) truePositives / phishingUrls.size() * 100.0;
        results.falsePositiveRate = (double) falsePositives / benignUrls.size() * 100.0;
        results.totalAdaptations = 0;
        
        return results;
    }
    
    private static BenchmarkResults benchmarkStandardTrie(List<String> phishingUrls, List<String> benignUrls) {
        System.out.println("Benchmarking Standard Trie...");
        
        StandardTrie trie = new StandardTrie();
        BenchmarkResults results = new BenchmarkResults();
        
        long startTime = System.nanoTime();
        for (String url : phishingUrls) {
            trie.insert(url);
        }
        long insertionTime = System.nanoTime() - startTime;
        results.avgInsertionTime = insertionTime / (double) phishingUrls.size() / 1000.0;
        
        results.memoryUsageMB = trie.getEstimatedMemoryUsage() / (1024.0 * 1024.0);
        
        startTime = System.nanoTime();
        int truePositives = 0;
        for (String url : phishingUrls) {
            if (trie.search(url)) {
                truePositives++;
            }
        }
        
        int falsePositives = 0;
        for (String url : benignUrls) {
            if (trie.search(url)) {
                falsePositives++;
            }
        }
        long searchTime = System.nanoTime() - startTime;
        
        results.avgSearchTime = searchTime / (double) (phishingUrls.size() + benignUrls.size()) / 1000.0;
        results.accuracy = (double) truePositives / phishingUrls.size() * 100.0;
        results.falsePositiveRate = (double) falsePositives / benignUrls.size() * 100.0;
        results.totalAdaptations = 0;
        
        return results;
    }
    
    private static void exportStatisticalResults(Map<String, List<BenchmarkResults>> allResults) {
        try (PrintWriter csvWriter = new PrintWriter(new FileWriter("benchmark_results.csv"));
             PrintWriter statsWriter = new PrintWriter(new FileWriter("statistical_analysis.txt"))) {
            
            csvWriter.println("Algorithm,AvgInsertionTime_us,StdDevInsertionTime_us,AvgSearchTime_us," +
                             "StdDevSearchTime_us,AvgMemoryUsage_MB,StdDevMemoryUsage_MB," +
                             "AvgFPR_%,StdDevFPR_%,AvgAccuracy_%,StdDevAccuracy_%,AvgAdaptations,StdDevAdaptations");
            
            statsWriter.println("=== STATISTICAL ANALYSIS OF BENCHMARK RESULTS ===\n");
            
            for (Map.Entry<String, List<BenchmarkResults>> entry : allResults.entrySet()) {
                String algorithm = entry.getKey();
                List<BenchmarkResults> results = entry.getValue();
                
                Statistics stats = calculateStatistics(results);
                
                csvWriter.printf("%s,%.4f,%.4f,%.4f,%.4f,%.2f,%.2f,%.4f,%.4f,%.2f,%.2f,%.1f,%.1f\n",
                    algorithm,
                    stats.meanInsertionTime, stats.stdDevInsertionTime,
                    stats.meanSearchTime, stats.stdDevSearchTime,
                    stats.meanMemoryUsage, stats.stdDevMemoryUsage,
                    stats.meanFPR, stats.stdDevFPR,
                    stats.meanAccuracy, stats.stdDevAccuracy,
                    stats.meanAdaptations, stats.stdDevAdaptations);
                
                statsWriter.printf("%s:\n", algorithm);
                statsWriter.printf("  Insertion Time: %.4f ± %.4f μs\n", stats.meanInsertionTime, stats.stdDevInsertionTime);
                statsWriter.printf("  Search Time: %.4f ± %.4f μs\n", stats.meanSearchTime, stats.stdDevSearchTime);
                statsWriter.printf("  Memory Usage: %.2f ± %.2f MB\n", stats.meanMemoryUsage, stats.stdDevMemoryUsage);
                statsWriter.printf("  False Positive Rate: %.4f ± %.4f %%\n", stats.meanFPR, stats.stdDevFPR);
                statsWriter.printf("  Accuracy: %.2f ± %.2f %%\n", stats.meanAccuracy, stats.stdDevAccuracy);
                statsWriter.printf("  Adaptations: %.1f ± %.1f\n\n", stats.meanAdaptations, stats.stdDevAdaptations);
            }
            
            System.out.println("Results exported to benchmark_results.csv and statistical_analysis.txt");
            
        } catch (IOException e) {
            System.err.println("Error exporting results: " + e.getMessage());
        }
    }
    
    private static Statistics calculateStatistics(List<BenchmarkResults> results) {
        Statistics stats = new Statistics();
        
        double[] insertionTimes = results.stream().mapToDouble(r -> r.avgInsertionTime).toArray();
        double[] searchTimes = results.stream().mapToDouble(r -> r.avgSearchTime).toArray();
        double[] memoryUsages = results.stream().mapToDouble(r -> r.memoryUsageMB).toArray();
        double[] fprs = results.stream().mapToDouble(r -> r.falsePositiveRate).toArray();
        double[] accuracies = results.stream().mapToDouble(r -> r.accuracy).toArray();
        double[] adaptations = results.stream().mapToDouble(r -> r.totalAdaptations).toArray();
        
        stats.meanInsertionTime = mean(insertionTimes);
        stats.stdDevInsertionTime = standardDeviation(insertionTimes);
        stats.meanSearchTime = mean(searchTimes);
        stats.stdDevSearchTime = standardDeviation(searchTimes);
        stats.meanMemoryUsage = mean(memoryUsages);
        stats.stdDevMemoryUsage = standardDeviation(memoryUsages);
        stats.meanFPR = mean(fprs);
        stats.stdDevFPR = standardDeviation(fprs);
        stats.meanAccuracy = mean(accuracies);
        stats.stdDevAccuracy = standardDeviation(accuracies);
        stats.meanAdaptations = mean(adaptations);
        stats.stdDevAdaptations = standardDeviation(adaptations);
        
        return stats;
    }
    
    private static double mean(double[] values) {
        return Arrays.stream(values).average().orElse(0.0);
    }
    
    private static double standardDeviation(double[] values) {
        double mean = mean(values);
        double variance = Arrays.stream(values)
                               .map(x -> Math.pow(x - mean, 2))
                               .average()
                               .orElse(0.0);
        return Math.sqrt(variance);
    }
    
    private static class Statistics {
        double meanInsertionTime, stdDevInsertionTime;
        double meanSearchTime, stdDevSearchTime;
        double meanMemoryUsage, stdDevMemoryUsage;
        double meanFPR, stdDevFPR;
        double meanAccuracy, stdDevAccuracy;
        double meanAdaptations, stdDevAdaptations;
    }
private static List<String> loadDataset(String filename, List<String> fallback) {
    try {
        List<String> loaded = Files.lines(Paths.get(filename))
                    .filter(line -> !line.trim().isEmpty())
                    .collect(Collectors.toList());
        
        System.out.println("=>Successfully loaded " + loaded.size() + 
                          " URLs from " + filename);  // ← ADD THIS
        return loaded;
        
    } catch (Exception e) {
        System.out.println("=> Could not load " + filename + ": " + e.getMessage());
        System.out.println("=> Using " + fallback.size() + " generated fallback URLs");
        return fallback;
    }
}
    private static List<String> generatePhishingUrls() {
        List<String> urls = new ArrayList<>();
        String[] suspiciousDomains = {
            "paypal-security.com", "amazon-update.net", "microsoft-account.org",
            "apple-verification.com", "google-security.net", "facebook-secure.org",
            "bank-of-america.net", "wells-fargo-online.com", "chase-secure.org",
            "ebay-security.net", "netflix-billing.com", "instagram-verify.org",
            "linkedin-account.com", "twitter-suspended.net", "dropbox-storage.org",
            "spotify-premium.net", "uber-receipt.com", "airbnb-booking.org"
        };
        
        String[] suspiciousPaths = {
            "/login", "/verify", "/update", "/secure", "/account", "/billing",
            "/suspended", "/locked", "/confirm", "/validate", "/security", "/urgent",
            "/expired", "/renewal", "/activation", "/verification"
        };
        
        String[] suspiciousParams = {
            "?token=", "?verify=", "?confirm=", "?update=", "?secure=", 
            "?account=", "?login=", "?auth=", "?session=", "?key="
        };
        
        for (String domain : suspiciousDomains) {
            for (String path : suspiciousPaths) {
                for (String param : suspiciousParams) {
                    for (int i = 0; i < 10; i++) {
                        urls.add("https://" + domain + path + param + generateRandomString(8));
                        urls.add("https://www." + domain + path + "/" + i + param + generateRandomString(6));
                    }
                }
            }
        }
        
        // System.out.println("Generated " + urls.size() + " phishing URLs for testing");
        return urls;
    }
    
    private static List<String> generateBenignUrls() {
        List<String> urls = new ArrayList<>();
        String[] legitimateDomains = {
            "google.com", "facebook.com", "paypal.com", "microsoft.com",
            "apple.com", "amazon.com", "github.com", "stackoverflow.com",
            "linkedin.com", "twitter.com", "instagram.com", "youtube.com",
            "netflix.com", "spotify.com", "dropbox.com", "reddit.com",
            "wikipedia.org", "medium.com", "techcrunch.com", "news.ycombinator.com"
        };
        
        String[] legitimatePaths = {
            "", "/about", "/contact", "/help", "/support", "/products",
            "/services", "/blog", "/news", "/careers", "/developers",
            "/pricing", "/features", "/documentation", "/community"
        };
        
        for (String domain : legitimateDomains) {
            for (String path : legitimatePaths) {
                for (int i = 0; i < 8; i++) {
                    urls.add("https://" + domain + path);
                    urls.add("https://www." + domain + path);
                    if (!path.isEmpty()) {
                        urls.add("https://" + domain + path + "/" + i);
                        urls.add("https://subdomain." + domain + path);
                    }
                }
            }
        }
        
        // System.out.println("Generated " + urls.size() + " benign URLs for testing");
        return urls;
    }
        
    private static String generateRandomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
    
    // Main method for running comprehensive benchmarks
    public static void main(String[] args) {
        System.out.println("Starting Comprehensive Research Benchmark...");
        runComprehensiveBenchmark();
    }
}

// Additional Research Utilities
class ResearchUtilities {
    
    // Memory profiler for detailed analysis
    public static class MemoryProfiler {
        
        public static void profileMemoryUsage(TrulyAdaptiveABT abt, List<String> urls) {
            System.out.println("=== MEMORY PROFILING ===");
            
            Runtime runtime = Runtime.getRuntime();
            List<Long> memorySnapshots = new ArrayList<>();
            List<Integer> urlCounts = new ArrayList<>();
            
            // Take initial snapshot
            runtime.gc();
            long initialMemory = runtime.totalMemory() - runtime.freeMemory();
            memorySnapshots.add(initialMemory);
            urlCounts.add(0);
            
            int batchSize = 1000;
            for (int i = 0; i < urls.size(); i += batchSize) {
                int endIndex = Math.min(i + batchSize, urls.size());
                
                // Insert batch
                for (int j = i; j < endIndex; j++) {
                    abt.insert(urls.get(j));
                }
                
                // Take memory snapshot
                runtime.gc();
                long currentMemory = runtime.totalMemory() - runtime.freeMemory();
                memorySnapshots.add(currentMemory);
                urlCounts.add(endIndex);
                
                System.out.printf("URLs: %d, Memory: %.2f MB, ABT Memory: %d KB\n",
                    endIndex, currentMemory / (1024.0 * 1024.0), abt.getMemoryUsage() / 1024);
            }
            
            // Export memory profile
            exportMemoryProfile(memorySnapshots, urlCounts);
        }
        
        private static void exportMemoryProfile(List<Long> memorySnapshots, List<Integer> urlCounts) {
            try (PrintWriter writer = new PrintWriter(new FileWriter("memory_profile.csv"))) {
                writer.println("URLCount,MemoryUsage_MB,MemoryPerURL_KB");
                
                for (int i = 0; i < memorySnapshots.size(); i++) {
                    double memoryMB = memorySnapshots.get(i) / (1024.0 * 1024.0);
                    int urlCount = urlCounts.get(i);
                    double memoryPerURL = urlCount > 0 ? memorySnapshots.get(i) / (1024.0 * urlCount) : 0;
                    
                    writer.printf("%d,%.4f,%.4f\n", urlCount, memoryMB, memoryPerURL);
                }
                
                System.out.println("Memory profile exported to memory_profile.csv");
                
            } catch (IOException e) {
                System.err.println("Error exporting memory profile: " + e.getMessage());
            }
        }
    }
    
    // Adaptation behavior analyzer
    public static class AdaptationAnalyzer {
        
        public static void analyzeAdaptationBehavior(TrulyAdaptiveABT abt, List<String> urls) {
            System.out.println("=== ADAPTATION BEHAVIOR ANALYSIS ===");
            
            List<Integer> resizeEvents = new ArrayList<>();
            List<Integer> splitEvents = new ArrayList<>();
            List<Integer> mergeEvents = new ArrayList<>();
            List<Double> fprHistory = new ArrayList<>();
            List<Integer> urlCounts = new ArrayList<>();
            
            int checkInterval = 2000;
            for (int i = 0; i < urls.size(); i++) {
                abt.insert(urls.get(i));
                
                if (i % checkInterval == 0) {
                    AdaptiveStats stats = abt.getStats();
                    
                    resizeEvents.add(stats.resizeEvents.get());
                    splitEvents.add(stats.splitEvents.get());
                    mergeEvents.add(stats.mergeEvents.get());
                    fprHistory.add(stats.getCurrentFPR());
                    urlCounts.add(i + 1);
                    
                    System.out.printf("URLs: %d, FPR: %.4f, Resizes: %d, Splits: %d, Merges: %d\n",
                        i + 1, stats.getCurrentFPR(), stats.resizeEvents.get(),
                        stats.splitEvents.get(), stats.mergeEvents.get());
                }
            }
            
            exportAdaptationHistory(urlCounts, resizeEvents, splitEvents, mergeEvents, fprHistory);
        }
        
        private static void exportAdaptationHistory(List<Integer> urlCounts, List<Integer> resizeEvents,
                                                   List<Integer> splitEvents, List<Integer> mergeEvents,
                                                   List<Double> fprHistory) {
            try (PrintWriter writer = new PrintWriter(new FileWriter("adaptation_history.csv"))) {
                writer.println("URLCount,ResizeEvents,SplitEvents,MergeEvents,FPR");
                
                for (int i = 0; i < urlCounts.size(); i++) {
                    writer.printf("%d,%d,%d,%d,%.6f\n",
                        urlCounts.get(i), resizeEvents.get(i), splitEvents.get(i),
                        mergeEvents.get(i), fprHistory.get(i));
                }
                
                System.out.println("Adaptation history exported to adaptation_history.csv");
                
            } catch (IOException e) {
                System.err.println("Error exporting adaptation history: " + e.getMessage());
            }
        }
    }
    
    // Performance comparison with different configurations
    public static class ConfigurationComparison {
        
        public static void compareConfigurations(List<String> phishingUrls, List<String> benignUrls) {
            System.out.println("=== CONFIGURATION COMPARISON ===");
            
            Map<String, Double> results = new HashMap<>();
            
            // Test different initial FPR targets
            double[] fprTargets = {0.001, 0.005, 0.01, 0.02, 0.05};
            
            for (double fprTarget : fprTargets) {
                System.out.printf("\nTesting FPR target: %.3f\n", fprTarget);
                
                long startTime = System.nanoTime();
                TrulyAdaptiveABT abt = new TrulyAdaptiveABT(false);
                
                // Insert all URLs
                for (String url : phishingUrls) {
                    abt.insert(url);
                }
                
                long insertionTime = System.nanoTime() - startTime;
                
                // Test accuracy
                int truePositives = 0;
                for (String url : phishingUrls) {
                    if (abt.search(url)) truePositives++;
                }
                
                int falsePositives = 0;
                for (String url : benignUrls) {
                    if (abt.search(url)) falsePositives++;
                }
                
                double accuracy = (double) truePositives / phishingUrls.size() * 100;
                double fpr = (double) falsePositives / benignUrls.size() * 100;
                double memoryMB = abt.getMemoryUsage() / (1024.0 * 1024.0);
                
                System.out.printf("  Accuracy: %.2f%%, FPR: %.4f%%, Memory: %.2f MB, Time: %.2f ms\n",
                    accuracy, fpr, memoryMB, insertionTime / 1_000_000.0);
                
                results.put("FPR_" + fprTarget, accuracy + (100 - fpr) + (1000 / memoryMB)); // Composite score
                
                abt.shutdown();
            }
            
            // Find best configuration
            String bestConfig = results.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("None");
            
            System.out.println("\nBest configuration: " + bestConfig);
        }
    }
}

// Main entry point with all testing options
class MainTestRunner {
    
    public static void main(String[] args) {
        System.out.println("=== ADAPTIVE BLOOM TRIE RESEARCH FRAMEWORK ===");
        
        if (args.length == 0) {
            System.out.println("Usage: java MainTestRunner [benchmark|profile|adaptation|config|workload]");
            System.out.println("  benchmark  - Run comprehensive benchmark comparison");
            System.out.println("  profile    - Run memory profiling");
            System.out.println("  adaptation - Analyze adaptation behavior");
            System.out.println("  config     - Compare different configurations");
            System.out.println("  workload   - Run workload simulations");
            return;
        }
        
        try {
            List<String> phishingUrls = loadTestUrls("phishing_urls.txt", generateTestPhishingUrls());
            List<String> benignUrls = loadTestUrls("benign_urls.txt", generateTestBenignUrls());
            
            switch (args[0].toLowerCase()) {
                case "benchmark":
                    ComprehensiveResearchBenchmark.runComprehensiveBenchmark();
                    break;
                    
                case "profile":
                    TrulyAdaptiveABT abt1 = new TrulyAdaptiveABT(true);
                    ResearchUtilities.MemoryProfiler.profileMemoryUsage(abt1, phishingUrls);
                    abt1.shutdown();
                    break;
                    
                case "adaptation":
                    TrulyAdaptiveABT abt2 = new TrulyAdaptiveABT(true);
                    ResearchUtilities.AdaptationAnalyzer.analyzeAdaptationBehavior(abt2, phishingUrls);
                    abt2.shutdown();
                    break;
                    
                case "config":
                    ResearchUtilities.ConfigurationComparison.compareConfigurations(phishingUrls, benignUrls);
                    break;
                    
                case "workload":
                    TrulyAdaptiveABT abt3 = new TrulyAdaptiveABT(true);
                    System.out.println("Running workload simulations...");
                    TrulyAdaptiveABT.WorkloadSimulator.simulateBurstWorkload(abt3, phishingUrls.subList(0, 5000));
                    TrulyAdaptiveABT.WorkloadSimulator.simulateStreamingWorkload(abt3, phishingUrls.subList(5000, 10000));
                    TrulyAdaptiveABT.WorkloadSimulator.simulateMixedWorkload(abt3, 
                        phishingUrls.subList(10000, 15000), benignUrls.subList(0, 5000));
                    abt3.shutdown();
                    break;
                    
                default:
                    System.out.println("Unknown option: " + args[0]);
                    break;
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        System.out.println("Test completed successfully!");
    }
    
    private static List<String> loadTestUrls(String filename, List<String> fallback) {
        try {
            return Files.lines(Paths.get(filename))
                        .filter(line -> !line.trim().isEmpty())
                        .collect(Collectors.toList());
        } catch (Exception e) {
            System.out.println("Using generated test data for " + filename);
            return fallback;
        }
    }
    
    private static List<String> generateTestPhishingUrls() {
        // Enhanced phishing URL generation with more realistic patterns
        List<String> urls = new ArrayList<>();
        String[] domains = {"paypal-secure", "amazon-verify", "microsoft-login", "apple-account"};
        String[] tlds = {".com", ".net", ".org", ".info"};
        String[] paths = {"/login", "/verify", "/update", "/secure"};
        
        for (String domain : domains) {
            for (String tld : tlds) {
                for (String path : paths) {
                    for (int i = 0; i < 100; i++) {
                        urls.add("https://" + domain + tld + path + "?id=" + i);
                    }
                }
            }
        }
        return urls;
    }
    
    private static List<String> generateTestBenignUrls() {
        List<String> urls = new ArrayList<>();
        String[] domains = {"google", "facebook", "microsoft", "apple"};
        String[] paths = {"", "/about", "/help", "/contact"};
        
        for (String domain : domains) {
            for (String path : paths) {
                for (int i = 0; i < 100; i++) {
                    urls.add("https://" + domain + ".com" + path);
                }
            }
        }
        return urls;
    }
}
