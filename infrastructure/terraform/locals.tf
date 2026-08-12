locals {
  rules = {
    "SF-001" = {
      name       = "sf-001-password-spray"
      title      = "Password spray across multiple Microsoft Entra ID accounts"
      severity   = "High"
      tactics    = ["CredentialAccess"]
      techniques = ["T1110.003"]
      query      = file("${path.root}/../../detections/rules/sf-001-password-spray/query.kql")
    }
    "SF-002" = {
      name       = "sf-002-failed-then-success"
      title      = "Repeated failed authentication followed by success"
      severity   = "High"
      tactics    = ["CredentialAccess", "InitialAccess"]
      techniques = ["T1110", "T1078.004"]
      query      = file("${path.root}/../../detections/rules/sf-002-failed-then-success/query.kql")
    }
    "SF-003" = {
      name       = "sf-003-impossible-travel"
      title      = "Anomalous geographic sign-in with impossible travel speed"
      severity   = "High"
      tactics    = ["InitialAccess"]
      techniques = ["T1078.004"]
      query      = file("${path.root}/../../detections/rules/sf-003-impossible-travel/query.kql")
    }
    "SF-004" = {
      name       = "sf-004-mfa-fatigue"
      title      = "Microsoft Entra ID MFA fatigue followed by approval"
      severity   = "High"
      tactics    = ["CredentialAccess"]
      techniques = ["T1621"]
      query      = file("${path.root}/../../detections/rules/sf-004-mfa-fatigue/query.kql")
    }
    "SF-005" = {
      name       = "sf-005-suspicious-powershell"
      title      = "Encoded or suspicious PowerShell execution"
      severity   = "High"
      tactics    = ["Execution", "DefenseEvasion"]
      techniques = ["T1059.001", "T1027"]
      query      = file("${path.root}/../../detections/rules/sf-005-suspicious-powershell/query.kql")
    }
    "SF-006" = {
      name       = "sf-006-lsass-access"
      title      = "Unapproved process access to LSASS memory"
      severity   = "High"
      tactics    = ["CredentialAccess"]
      techniques = ["T1003.001"]
      query      = file("${path.root}/../../detections/rules/sf-006-lsass-access/query.kql")
    }
    "SF-007" = {
      name       = "sf-007-dcsync"
      title      = "Unapproved directory replication consistent with DCSync"
      severity   = "High"
      tactics    = ["CredentialAccess"]
      techniques = ["T1003.006"]
      query      = file("${path.root}/../../detections/rules/sf-007-dcsync/query.kql")
    }
    "SF-008" = {
      name       = "sf-008-rdp-lateral-movement"
      title      = "RDP lateral movement across multiple devices"
      severity   = "High"
      tactics    = ["LateralMovement"]
      techniques = ["T1021.001"]
      query      = file("${path.root}/../../detections/rules/sf-008-rdp-lateral-movement/query.kql")
    }
    "SF-009" = {
      name       = "sf-009-unauthorized-remote-tool"
      title      = "Unauthorized AnyDesk or TeamViewer execution"
      severity   = "High"
      tactics    = ["CommandAndControl"]
      techniques = ["T1219.002"]
      query      = file("${path.root}/../../detections/rules/sf-009-unauthorized-remote-tool/query.kql")
    }
    "SF-010" = {
      name       = "sf-010-dns-tunneling"
      title      = "DNS tunnelling indicators from long unique labels"
      severity   = "Medium"
      tactics    = ["CommandAndControl"]
      techniques = ["T1071.004"]
      query      = file("${path.root}/../../detections/rules/sf-010-dns-tunneling/query.kql")
    }
    "SF-011" = {
      name       = "sf-011-aws-iam-anomaly"
      title      = "Anomalous AWS IAM administrative API activity"
      severity   = "High"
      tactics    = ["Persistence", "PrivilegeEscalation"]
      techniques = ["T1098.001", "T1098"]
      query      = file("${path.root}/../../detections/rules/sf-011-aws-iam-anomaly/query.kql")
    }
    "SF-012" = {
      name       = "sf-012-outbound-beaconing"
      title      = "Palo Alto-style periodic outbound beaconing"
      severity   = "Medium"
      tactics    = ["CommandAndControl"]
      techniques = ["T1071.001"]
      query      = file("${path.root}/../../detections/rules/sf-012-outbound-beaconing/query.kql")
    }
  }
}
