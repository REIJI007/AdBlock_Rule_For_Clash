using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

public static class SemanticAuditEngine
{
    public sealed class Mismatch
    {
        public string domain { get; set; }
        public string upstreamStatus { get; set; }
        public bool artifactBlocked { get; set; }
        public string reason { get; set; }
    }

    public sealed class Result
    {
        public long TP { get; set; }
        public long FP { get; set; }
        public long TN { get; set; }
        public long FN { get; set; }
        public long BoundaryCount { get; set; }
        public long RepresentativeSubdomainCount { get; set; }
        public long UnrepresentableSubdomainBoundaryCount { get; set; }
        public long EvaluationPointCount { get { return TP + FP + TN + FN; } }
        public double BoundaryBuildDurationSeconds { get; set; }
        public double SemanticEvaluationDurationSeconds { get; set; }
        public List<Mismatch> FalsePositiveExamples { get; private set; }
        public List<Mismatch> FalseNegativeExamples { get; private set; }

        public Result()
        {
            FalsePositiveExamples = new List<Mismatch>();
            FalseNegativeExamples = new List<Mismatch>();
        }
    }

    private static void AddBoundaryAndParents(string domain, HashSet<string> boundaries)
    {
        boundaries.Add(domain);
        int dot = domain.IndexOf('.');
        while (dot >= 0)
        {
            int parentStart = dot + 1;
            int nextDot = domain.IndexOf('.', parentStart);
            if (nextDot < 0) break; // Do not add a top-level domain as a rule boundary.
            boundaries.Add(domain.Substring(parentStart));
            dot = nextDot;
        }
    }

    private static bool HasSuffixRule(string domain, HashSet<string> rules)
    {
        int start = 0;
        int dot = domain.IndexOf('.');
        while (dot >= 0)
        {
            if (rules.Contains(domain.Substring(start))) return true;
            start = dot + 1;
            dot = domain.IndexOf('.', start);
        }
        return false;
    }

    private static string EffectiveStatus(
        string domain,
        HashSet<string> importantWhitelistExact,
        HashSet<string> importantWhitelistSuffix,
        HashSet<string> importantExact,
        HashSet<string> importantSuffix,
        HashSet<string> excludedExact,
        HashSet<string> excludedSuffix,
        HashSet<string> validExact,
        HashSet<string> validSuffix)
    {
        if (importantWhitelistExact.Contains(domain) ||
            HasSuffixRule(domain, importantWhitelistSuffix))
            return "WHITELIST_P0";

        if (importantExact.Contains(domain) ||
            HasSuffixRule(domain, importantSuffix))
            return "BLACKLIST_P1";

        int start = 0;
        int dot = domain.IndexOf('.');
        while (dot >= 0)
        {
            string current = domain.Substring(start);
            if (start == 0 && excludedExact.Contains(current))
                return "WHITELIST_P2";
            if (excludedSuffix.Contains(current))
                return "WHITELIST_P2";
            if (start == 0 && validExact.Contains(current))
                return "BLACKLIST_P3";
            if (validSuffix.Contains(current))
                return "BLACKLIST_P4";

            start = dot + 1;
            dot = domain.IndexOf('.', start);
        }
        return "UNKNOWN";
    }

    private static bool ArtifactBlocks(
        string domain,
        HashSet<string> artifactExact,
        HashSet<string> artifactSuffix)
    {
        if (artifactExact.Contains(domain) || artifactSuffix.Contains(domain))
            return true;

        int dot = domain.IndexOf('.');
        while (dot >= 0)
        {
            int suffixStart = dot + 1;
            int nextDot = domain.IndexOf('.', suffixStart);
            if (nextDot < 0) break; // Do not match the TLD as a DOMAIN-SUFFIX.
            if (artifactSuffix.Contains(domain.Substring(suffixStart)))
                return true;
            dot = nextDot;
        }
        return false;
    }

    private static void AddPoint(
        string domain,
        Result result,
        HashSet<string> artifactExact,
        HashSet<string> artifactSuffix,
        HashSet<string> importantWhitelistExact,
        HashSet<string> importantWhitelistSuffix,
        HashSet<string> importantExact,
        HashSet<string> importantSuffix,
        HashSet<string> excludedExact,
        HashSet<string> excludedSuffix,
        HashSet<string> validExact,
        HashSet<string> validSuffix,
        int maxExamples)
    {
        string status = EffectiveStatus(
            domain, importantWhitelistExact, importantWhitelistSuffix,
            importantExact, importantSuffix, excludedExact, excludedSuffix,
            validExact, validSuffix);
        bool expectedBlocked = status.StartsWith("BLACKLIST", StringComparison.Ordinal);
        bool actualBlocked = ArtifactBlocks(domain, artifactExact, artifactSuffix);

        if (expectedBlocked && actualBlocked)
        {
            result.TP++;
        }
        else if (expectedBlocked)
        {
            result.FN++;
            if (result.FalseNegativeExamples.Count < maxExamples)
            {
                result.FalseNegativeExamples.Add(new Mismatch {
                    domain = domain,
                    upstreamStatus = status,
                    artifactBlocked = false,
                    reason = "完整上游有效规则要求拦截，但正式产物未命中"
                });
            }
        }
        else if (actualBlocked)
        {
            result.FP++;
            if (result.FalsePositiveExamples.Count < maxExamples)
            {
                result.FalsePositiveExamples.Add(new Mismatch {
                    domain = domain,
                    upstreamStatus = status,
                    artifactBlocked = true,
                    reason = "完整上游有效规则未要求拦截，但正式产物发生了拦截"
                });
            }
        }
        else
        {
            result.TN++;
        }
    }

    public static Result Evaluate(
        HashSet<string> upstreamDomains,
        HashSet<string> artifactExact,
        HashSet<string> artifactSuffix,
        HashSet<string> importantWhitelistExact,
        HashSet<string> importantWhitelistSuffix,
        HashSet<string> importantExact,
        HashSet<string> importantSuffix,
        HashSet<string> excludedExact,
        HashSet<string> excludedSuffix,
        HashSet<string> validExact,
        HashSet<string> validSuffix,
        int maxExamples)
    {
        var result = new Result();
        var boundaryTimer = Stopwatch.StartNew();
        var boundaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string domain in upstreamDomains)
            AddBoundaryAndParents(domain, boundaries);
        foreach (string domain in artifactExact)
            AddBoundaryAndParents(domain, boundaries);
        foreach (string domain in artifactSuffix)
            AddBoundaryAndParents(domain, boundaries);

        boundaryTimer.Stop();
        result.BoundaryBuildDurationSeconds = boundaryTimer.Elapsed.TotalSeconds;
        result.BoundaryCount = boundaries.Count;

        var evaluationTimer = Stopwatch.StartNew();
        long processed = 0;

        foreach (string domain in boundaries)
        {
            AddPoint(domain, result, artifactExact, artifactSuffix,
                importantWhitelistExact, importantWhitelistSuffix,
                importantExact, importantSuffix, excludedExact, excludedSuffix,
                validExact, validSuffix, maxExamples);

            if (domain.Length <= 251)
            {
                string probeDomain = "q." + domain;
                int probeIndex = 0;
                while (boundaries.Contains(probeDomain))
                {
                    probeIndex++;
                    string probeLabel = "q" + probeIndex.ToString(CultureInfo.InvariantCulture);
                    if (probeLabel.Length > 63)
                    {
                        probeDomain = null;
                        break;
                    }
                    probeDomain = probeLabel + "." + domain;
                    if (probeDomain.Length > 253)
                    {
                        probeDomain = null;
                        break;
                    }
                }

                if (probeDomain != null)
                {
                    AddPoint(probeDomain, result, artifactExact, artifactSuffix,
                        importantWhitelistExact, importantWhitelistSuffix,
                        importantExact, importantSuffix, excludedExact, excludedSuffix,
                        validExact, validSuffix, maxExamples);
                    result.RepresentativeSubdomainCount++;
                }
                else
                {
                    result.UnrepresentableSubdomainBoundaryCount++;
                }
            }
            else
            {
                result.UnrepresentableSubdomainBoundaryCount++;
            }

            processed++;
            if (processed % 100000 == 0)
                Console.WriteLine("已评估 {0:N0} / {1:N0} 个域名边界...", processed, boundaries.Count);
        }

        evaluationTimer.Stop();
        result.SemanticEvaluationDurationSeconds = evaluationTimer.Elapsed.TotalSeconds;
        return result;
    }
}