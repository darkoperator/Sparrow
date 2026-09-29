use sparrow_synth::conformance::{
    conform_layouts, conform_real, profile_dir, recorded_culture_forms,
};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{builtin_names, load};
use std::collections::{BTreeMap, BTreeSet};

/// Every per-culture date form the layouts record must really be produced by the generator:
/// a per-culture key is a claim that the writer renders that column in the host culture, so a
/// column the writer emits as fixed service text (a literal ISO string) must carry none. This
/// catches a layouts entry that grants a form no tree ever shows.
#[test]
fn no_dead_culture_forms_are_recorded() {
    let claims = recorded_culture_forms();
    assert!(!claims.is_empty(), "no per-culture forms recorded at all");
    // (artifact, column, culture) -> the forms the generated matrix actually shows.
    let mut seen: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            for ps in [PsEdition::Ps7, PsEdition::Ps51] {
                for culture in [Culture::EnUs, Culture::EnGb, Culture::DeDe] {
                    let dir = tempfile::tempdir().unwrap();
                    let mut o = GenerateOptions::new(*c, 5);
                    o.ps = ps;
                    o.culture = culture;
                    generate_to_dir(&load(name).unwrap(), &o, dir.path()).unwrap();
                    for (art, ap) in &profile_dir(dir.path()).unwrap().artifacts {
                        for (col, forms) in &ap.dates {
                            seen.entry((art.clone(), col.clone(), format!("{culture:?}")))
                                .or_default()
                                .extend(forms.iter().cloned());
                        }
                    }
                }
            }
        }
    }
    let dead: Vec<String> = claims
        .iter()
        .filter(|(art, col, culture, form)| {
            !seen
                .get(&(art.clone(), col.clone(), format!("{culture:?}")))
                .is_some_and(|fs| fs.contains(form))
        })
        .map(|(art, col, culture, form)| format!("{art} {col} {culture:?} {form}"))
        .collect();
    assert!(dead.is_empty(), "recorded but never generated: {dead:#?}");
}

fn r#gen(
    name: &str,
    c: Collector,
    ps: PsEdition,
) -> (tempfile::TempDir, sparrow_synth::manifest::Manifest) {
    r#gen_culture(name, c, ps, Culture::EnUs)
}

fn r#gen_culture(
    name: &str,
    c: Collector,
    ps: PsEdition,
    culture: Culture,
) -> (tempfile::TempDir, sparrow_synth::manifest::Manifest) {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(c, 5);
    o.ps = ps;
    o.culture = culture;
    let m = generate_to_dir(&load(name).unwrap(), &o, dir.path()).unwrap();
    (dir, m)
}

/// Fast representative of the every-scenario matrix below: bec-aitm for every collector and
/// edition on en-US, plus the day-first cultures on PS7.
#[test]
fn bec_aitm_conforms_to_the_recorded_layouts() {
    for c in Collector::ALL {
        for (ps, culture) in [
            (PsEdition::Ps7, Culture::EnUs),
            (PsEdition::Ps51, Culture::EnUs),
            (PsEdition::Ps7, Culture::EnGb),
            (PsEdition::Ps7, Culture::DeDe),
        ] {
            let (dir, _) = r#gen_culture("bec-aitm", *c, ps, culture);
            let p = profile_dir(dir.path()).unwrap();
            let r = conform_layouts(&p, *c, Some(culture));
            assert!(r.ok, "bec-aitm {c:?} {ps:?} {culture:?}:\n{}", r.to_text());
            assert!(
                r.checked > 0,
                "bec-aitm {c:?} {ps:?} {culture:?}: nothing checked"
            );
        }
    }
}

/// Every built-in scenario (except `volume`) for every collector, edition and the three host
/// cultures must match the recorded layouts. A culture picks the per-culture date forms the
/// layouts record for it (en-GB/de-DE render a CSV date day-first).
#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn generated_trees_conform_to_the_recorded_layouts() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            for ps in [PsEdition::Ps7, PsEdition::Ps51] {
                for culture in [Culture::EnUs, Culture::EnGb, Culture::DeDe] {
                    let (dir, _) = r#gen_culture(name, *c, ps, culture);
                    let p = profile_dir(dir.path()).unwrap();
                    let r = conform_layouts(&p, *c, Some(culture));
                    assert!(r.ok, "{name} {c:?} {ps:?} {culture:?}:\n{}", r.to_text());
                    assert!(
                        r.checked > 0,
                        "{name} {c:?} {ps:?} {culture:?}: nothing checked"
                    );
                }
            }
        }
    }
}

/// Hawk 3's `Tenant/All_InboxRules` is a single JSON document (capture survey §2b: it is
/// byte-identical to a user's `InboxRules_<u>`), so its shape is a bare object or an array,
/// never the concatenated documents a per-user `-Append` would leave.
#[test]
fn hawk3_all_inbox_rules_is_a_single_json_document() {
    let (dir, _) = r#gen("bec-aitm", Collector::Hawk3, PsEdition::Ps7);
    let p = profile_dir(dir.path()).unwrap();
    let ap = p
        .artifacts
        .get("hawk.tenant.all_inbox_rules")
        .expect("hawk.tenant.all_inbox_rules");
    assert!(ap.json_shapes.contains_key("array"), "{:?}", ap.json_shapes);
    assert!(
        !ap.json_shapes.contains_key("concatenated"),
        "{:?}",
        ap.json_shapes
    );
}

/// The world now holds a partner remote domain and 3+ eDiscovery role assignments, so the
/// The raw UAL `CreationDate` DateTime's .NET Kind follows the Exchange Online module build, so
/// the survey saw both a zone-less ISO rendering (capture B) and `…Z` (the C/D tenant files).
/// The generator picks one per tree from the seed: two seeds give both forms, and no single tree
/// ever mixes them inside one file.
#[test]
fn ual_creation_date_kind_is_one_choice_per_tree() {
    // The raw UAL / Simple / investigate file families that carry the column.
    const PREFIXES: &[&str] = &[
        "Raw_Authentication_Logs",
        "Simple_",
        "eDiscoveryLogs",
        "_Investigate_",
        "ExchangeItem_Logs",
        "User_Changes",
        "Exchange_UAL_Audit",
    ];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for seed in 1..=8u64 {
        let dir = tempfile::tempdir().unwrap();
        let o = GenerateOptions::new(Collector::Hawk4, seed);
        generate_to_dir(&load("bec-aitm").unwrap(), &o, dir.path()).unwrap();
        let per_file = creation_date_forms(dir.path());
        assert!(!per_file.is_empty(), "seed {seed}: no raw UAL JSON found");
        for (file, forms) in &per_file {
            if !PREFIXES.iter().any(|p| file.starts_with(p)) {
                continue;
            }
            // One form per file: the choice is per tree, never mixed inside a document.
            let set: BTreeSet<&str> = forms.iter().map(String::as_str).collect();
            assert!(set.len() <= 1, "seed {seed} {file} mixes {set:?}");
            for f in set {
                assert!(
                    matches!(f, "iso_z" | "iso_nozone" | "culture_mdy"),
                    "seed {seed} {file}: unexpected CreationDate form {f}"
                );
                seen.insert(f.to_string());
            }
        }
    }
    assert!(
        seen.contains("iso_z"),
        "no seed produced the Z form: {seen:?}"
    );
    assert!(
        seen.contains("iso_nozone"),
        "no seed produced the zone-less form: {seen:?}"
    );
}

/// Every generated JSON file's `CreationDate` date form, keyed by file name.
fn creation_date_forms(path: &std::path::Path) -> BTreeMap<String, BTreeSet<String>> {
    use sparrow_synth::conformance::classify_date;
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "json") {
                let text = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).to_string();
                let mut forms = BTreeSet::new();
                let mut rest = text.as_str();
                while let Some(i) = rest.find("\"CreationDate\": \"") {
                    let after = &rest[i + "\"CreationDate\": \"".len()..];
                    let value = after.split('"').next().unwrap_or("");
                    if let Some(f) = classify_date(value) {
                        forms.insert(f.to_string());
                    }
                    rest = after;
                }
                if !forms.is_empty() {
                    out.insert(p.file_name().unwrap().to_string_lossy().to_string(), forms);
                }
            }
        }
    }
    out
}

/// generated trees produce arrays for both (the real captures' shape).
#[test]
fn generated_remote_domain_and_ediscovery_role_assignments_are_arrays() {
    for c in [Collector::Hawk3, Collector::Hawk4] {
        let (dir, _) = r#gen("bec-aitm", c, PsEdition::Ps7);
        let p = profile_dir(dir.path()).unwrap();
        for a in [
            "hawk.tenant.remote_domain",
            "hawk.tenant.ediscovery_role_assignments",
        ] {
            let Some(ap) = p.artifacts.get(a) else {
                continue;
            };
            assert!(
                ap.json_shapes.contains_key("array"),
                "{a} {c:?}: {:?}",
                ap.json_shapes
            );
            assert!(
                !ap.json_shapes.contains_key("bare"),
                "{a} {c:?}: {:?}",
                ap.json_shapes
            );
        }
    }
}

/// Task F4: the Exchange object and inbox-rule artifacts carry the full column sets the real
/// captures hold. The names are the Exchange/Graph schema property names `conformance --real`
/// found missing (the cmdlets' output columns), the values are neutral defaults or derived
/// from the synthetic world.
#[test]
fn exchange_objects_carry_their_full_column_sets() {
    const EXPECTED: &[(&str, &[&str])] = &[
        (
            "hawk.tenant.remote_domain",
            &[
                "ByteEncoderTypeFor7BitCharsets",
                "DirectoryObjectVersion",
                "ExchangeObjectId",
                "ExchangeVersion",
                "Guid",
                "MessageCountThreshold",
                "NDRDiagnosticInfoEnabled",
                "NDREnabled",
                "NonMimeCharacterSet",
                "ObjectCategory",
                "ObjectClass",
                "OrganizationalUnitRoot",
                "OriginatingServer",
                "PreferredInternetCodePageForShiftJis",
                "RequiredCharsetCoverage",
                "SmtpDaneMandatoryModeEnabled",
            ],
        ),
        (
            "hawk.tenant.transport_config",
            &[
                "AgentGeneratedMessageLoopDetectionInSmtpEnabled",
                "AgentGeneratedMessageLoopDetectionInSubmissionEnabled",
                "AnonymousSenderToRecipientRatePerHour",
                "AttributionRejectBeforeMServRequest",
                "AttributionRejectConsumerMessages",
                "ConvertReportToMessage",
                "CurrentTransportSystemState",
                "DiagnosticsAggregationServicePort",
                "DirectoryObjectVersion",
                "EnableExternalHTTPMailDelivery",
                "ExchangeObjectId",
                "ExchangeVersion",
                "ExternalDsnDefaultLanguage",
                "ExternalDsnLanguageDetectionEnabled",
                "ExternalDsnMaxMessageAttachSize",
                "ExternalDsnReportingAuthority",
                "ExternalDsnSendHtml",
                "GenerateCopyOfDSNFor",
                "HeaderPromotionModeSetting",
                "HygieneSuite",
                "Id",
                "InternalDelayDsnEnabled",
                "InternalDsnDefaultLanguage",
                "InternalDsnLanguageDetectionEnabled",
                "InternalDsnMaxMessageAttachSize",
                "InternalDsnReportingAuthority",
                "InternalDsnSendHtml",
                "JournalArchivingEnabled",
                "JournalMessageExpirationDays",
                "JournalReportDLMemberSubstitutionEnabled",
                "LegacyArchiveJournalingEnabled",
                "LegacyArchiveLiveJournalingEnabled",
                "LegacyJournalingMigrationEnabled",
                "MaxAllowedAgentGeneratedMessageDepth",
                "MaxAllowedAgentGeneratedMessageDepthPerAgent",
                "MaxDumpsterSizePerDatabase",
                "MaxDumpsterTime",
                "MessageExpiration",
                "MigrationEnabled",
                "ObjectCategory",
                "ObjectClass",
                "OpenDomainRoutingEnabled",
                "OrganizationFederatedMailbox",
                "OrganizationalUnitRoot",
                "OriginatingServer",
                "OtherWellKnownObjects",
                "PreserveReportBodypart",
                "PreventDuplicateJournalingEnabled",
                "QueueDiagnosticsAggregationInterval",
                "RedirectDLMessagesForLegacyArchiveJournaling",
                "RedirectUnprovisionedUserMessagesForLegacyArchiveJournaling",
                "ReplyAllStormBlockDurationHours",
                "ReplyAllStormDetectionMinimumRecipients",
                "ReplyAllStormDetectionMinimumReplies",
                "ReplyAllStormProtectionEnabled",
                "Rfc2231EncodingEnabled",
                "SafetyNetHoldTime",
                "SupervisionTags",
                "TransportRuleAttachmentTextScanLimit",
                "TransportRuleCollectionAddedRecipientsLimit",
                "TransportRuleCollectionRegexCharsLimit",
                "TransportRuleConfig",
                "TransportRuleLimit",
                "TransportRuleRegexValidationTimeout",
                "TransportRuleSizeLimit",
                "TransportSystemState",
                "VerifySecureSubmitEnabled",
                "Xexch50Enabled",
            ],
        ),
        (
            "hawk.tenant.transport_rules",
            &[
                "ADComparisonAttribute",
                "ADComparisonOperator",
                "AddManagerAsRecipientType",
                "AnyOfCcHeader",
                "AnyOfCcHeaderMemberOf",
                "AnyOfRecipientAddressContainsWords",
                "AnyOfRecipientAddressMatchesPatterns",
                "AnyOfToCcHeader",
                "AnyOfToCcHeaderMemberOf",
                "AnyOfToHeader",
                "AnyOfToHeaderMemberOf",
                "ApplyClassification",
                "ApplyHtmlDisclaimerFallbackAction",
                "ApplyHtmlDisclaimerLocation",
                "ApplyHtmlDisclaimerText",
                "ApplyOME",
                "ApplyRightsProtectionCustomizationTemplate",
                "ApplyRightsProtectionTemplate",
                "AttachmentContainsWords",
                "AttachmentExtensionMatchesWords",
                "AttachmentHasExecutableContent",
                "AttachmentIsPasswordProtected",
                "AttachmentIsUnsupported",
                "AttachmentMatchesPatterns",
                "AttachmentNameMatchesPatterns",
                "AttachmentProcessingLimitExceeded",
                "AttachmentPropertyContainsWords",
                "AttachmentSizeOver",
                "BetweenMemberOf1",
                "BetweenMemberOf2",
                "ContentCharacterSetContainsWords",
                "ContentMatchesPrompt",
                "ContentMatchesPromptFallbackResult",
                "ContentMatchesPromptScanScope",
                "ContentMatchesPromptVerdict",
                "CreatedBy",
                "DeleteMessage",
                "Disconnect",
                "ExceptIfADComparisonAttribute",
                "ExceptIfADComparisonOperator",
                "ExceptIfAnyOfCcHeader",
                "ExceptIfAnyOfCcHeaderMemberOf",
                "ExceptIfAnyOfRecipientAddressContainsWords",
                "ExceptIfAnyOfRecipientAddressMatchesPatterns",
                "ExceptIfAnyOfToCcHeader",
                "ExceptIfAnyOfToCcHeaderMemberOf",
                "ExceptIfAnyOfToHeader",
                "ExceptIfAnyOfToHeaderMemberOf",
                "ExceptIfAttachmentContainsWords",
                "ExceptIfAttachmentExtensionMatchesWords",
                "ExceptIfAttachmentHasExecutableContent",
                "ExceptIfAttachmentIsPasswordProtected",
                "ExceptIfAttachmentIsUnsupported",
                "ExceptIfAttachmentMatchesPatterns",
                "ExceptIfAttachmentNameMatchesPatterns",
                "ExceptIfAttachmentProcessingLimitExceeded",
                "ExceptIfAttachmentPropertyContainsWords",
                "ExceptIfAttachmentSizeOver",
                "ExceptIfBetweenMemberOf1",
                "ExceptIfBetweenMemberOf2",
                "ExceptIfContentCharacterSetContainsWords",
                "ExceptIfContentMatchesPrompt",
                "ExceptIfContentMatchesPromptFallbackResult",
                "ExceptIfContentMatchesPromptScanScope",
                "ExceptIfContentMatchesPromptVerdict",
                "ExceptIfFrom",
                "ExceptIfFromAddressContainsWords",
                "ExceptIfFromAddressMatchesPatterns",
                "ExceptIfFromMemberOf",
                "ExceptIfFromScope",
                "ExceptIfHasClassification",
                "ExceptIfHasNoClassification",
                "ExceptIfHasSenderOverride",
                "ExceptIfHeaderContainsMessageHeader",
                "ExceptIfHeaderContainsWords",
                "ExceptIfHeaderMatchesMessageHeader",
                "ExceptIfHeaderMatchesPatterns",
                "ExceptIfManagerAddresses",
                "ExceptIfManagerForEvaluatedUser",
                "ExceptIfMessageContainsAllDataClassifications",
                "ExceptIfMessageContainsDataClassifications",
                "ExceptIfMessageSizeOver",
                "ExceptIfMessageTypeMatches",
                "ExceptIfRecipientADAttributeContainsWords",
                "ExceptIfRecipientADAttributeMatchesPatterns",
                "ExceptIfRecipientAddressContainsWords",
                "ExceptIfRecipientAddressMatchesPatterns",
                "ExceptIfRecipientDomainIs",
                "ExceptIfRecipientInSenderList",
                "ExceptIfSCLOver",
                "ExceptIfSenderADAttributeContainsWords",
                "ExceptIfSenderADAttributeMatchesPatterns",
                "ExceptIfSenderDomainIs",
                "ExceptIfSenderInRecipientList",
                "ExceptIfSenderIpRanges",
                "ExceptIfSenderManagementRelationship",
                "ExceptIfSentTo",
                "ExceptIfSentToMemberOf",
                "ExceptIfSentToScope",
                "ExceptIfSubjectContainsWords",
                "ExceptIfSubjectMatchesPatterns",
                "ExceptIfSubjectOrBodyContainsWords",
                "ExceptIfSubjectOrBodyMatchesPatterns",
                "ExceptIfWithImportance",
                "ExchangeVersion",
                "From",
                "FromAddressContainsWords",
                "FromAddressMatchesPatterns",
                "FromMemberOf",
                "FromScope",
                "GenerateIncidentReport",
                "GenerateNotification",
                "HasClassification",
                "HasNoClassification",
                "HasSenderOverride",
                "HeaderContainsMessageHeader",
                "HeaderContainsWords",
                "HeaderMatchesMessageHeader",
                "HeaderMatchesPatterns",
                "IncidentReportContent",
                "IsRuleConfigurationSupported",
                "LogEventText",
                "ManagerAddresses",
                "ManagerForEvaluatedUser",
                "MessageContainsAllDataClassifications",
                "MessageContainsDataClassifications",
                "MessageSizeOver",
                "MessageTypeMatches",
                "ModerateMessageByManager",
                "ModerateMessageByUser",
                "PrependSubject",
                "Quarantine",
                "RecipientADAttributeContainsWords",
                "RecipientADAttributeMatchesPatterns",
                "RecipientAddressContainsWords",
                "RecipientAddressMatchesPatterns",
                "RecipientAddressType",
                "RecipientDomainIs",
                "RecipientInSenderList",
                "RegexSize",
                "RejectMessageReasonText",
                "RemoveHeader",
                "RemoveOME",
                "RemoveOMEv2",
                "RemoveRMSAttachmentEncryption",
                "RouteMessageOutboundConnector",
                "RouteMessageOutboundRequireTls",
                "RuleConfigurationUnsupportedReason",
                "SCLOver",
                "SenderADAttributeContainsWords",
                "SenderADAttributeMatchesPatterns",
                "SenderDomainIs",
                "SenderInRecipientList",
                "SenderIpRanges",
                "SenderManagementRelationship",
                "SenderNotificationType",
                "SentTo",
                "SentToMemberOf",
                "SetAuditSeverity",
                "SetHeaderName",
                "SetHeaderValue",
                "SetSCL",
                "Size",
                "SmtpRejectMessageRejectStatusCode",
                "SmtpRejectMessageRejectText",
                "StopRuleProcessing",
                "SubjectContainsWords",
                "SubjectMatchesPatterns",
                "SubjectOrBodyContainsWords",
                "SubjectOrBodyMatchesPatterns",
                "WithImportance",
            ],
        ),
        (
            "hawk.user.inbox_rules",
            &[
                "AnyCategory",
                "ApplySystemCategory",
                "AssignedCategories",
                "AutoReplyWithTemplate",
                "BulkCategory",
                "ClearCategories",
                "ClearFlag",
                "CompleteFlag",
                "DeleteSystemCategory",
                "DisplayAlert",
                "ExceptIfAnyCategory",
                "ExceptIfAssignedCategories",
                "ExceptIfBulkCategory",
                "ExceptIfFlaggedForAction",
                "ExceptIfFromAddressContainsWords",
                "ExceptIfHasClassification",
                "ExceptIfHeaderContainsWords",
                "ExceptIfIsExternal",
                "ExceptIfIsMentioned",
                "ExceptIfMessageTypeMatches",
                "ExceptIfMyNameInCcBox",
                "ExceptIfMyNameInToBox",
                "ExceptIfMyNameInToOrCcBox",
                "ExceptIfMyNameNotInToBox",
                "ExceptIfReceivedAfterDate",
                "ExceptIfReceivedBeforeDate",
                "ExceptIfRecipientAddressContainsWords",
                "ExceptIfSentOnlyToMe",
                "ExceptIfSentTo",
                "ExceptIfSubjectContainsWords",
                "ExceptIfSubjectOrBodyContainsWords",
                "ExceptIfWithImportance",
                "ExceptIfWithSensitivity",
                "ExceptIfWithinSizeRangeMaximum",
                "ExceptIfWithinSizeRangeMinimum",
                "FlagMessage",
                "HasClassification",
                "HeaderContainsWords",
                "IsExternal",
                "IsMentioned",
                "MyNameInCcBox",
                "MyNameInToBox",
                "MyNameNotInToBox",
                "PermanentDelete",
                "PinMessage",
                "PlaySound",
                "ReceivedAfterDate",
                "ReceivedBeforeDate",
                "RecipientAddressContainsWords",
                "SentTo",
                "WithSensitivity",
            ],
        ),
        (
            "hawk.tenant.all_inbox_rules",
            &[
                "ApplySystemCategory",
                "DeleteSystemCategory",
                "ExceptIfFlaggedForAction",
                "ExceptIfFromAddressContainsWords",
                "ExceptIfHasClassification",
                "ExceptIfHeaderContainsWords",
                "ExceptIfMessageTypeMatches",
                "ExceptIfMyNameInCcBox",
                "ExceptIfMyNameInToBox",
                "ExceptIfMyNameInToOrCcBox",
                "ExceptIfMyNameNotInToBox",
                "ExceptIfReceivedAfterDate",
                "ExceptIfReceivedBeforeDate",
                "ExceptIfRecipientAddressContainsWords",
                "ExceptIfSentOnlyToMe",
                "ExceptIfSentTo",
                "ExceptIfSubjectContainsWords",
                "ExceptIfSubjectOrBodyContainsWords",
                "ExceptIfWithImportance",
                "ExceptIfWithSensitivity",
                "ExceptIfWithinSizeRangeMaximum",
                "ExceptIfWithinSizeRangeMinimum",
                "HasClassification",
                "HeaderContainsWords",
                "MyNameInCcBox",
                "MyNameInToBox",
                "MyNameNotInToBox",
                "PinMessage",
                "ReceivedAfterDate",
                "ReceivedBeforeDate",
                "RecipientAddressContainsWords",
                "SentTo",
                "WithSensitivity",
            ],
        ),
        (
            "hawk.tenant.ediscovery_role_assignments",
            &["ExchangeVersion"],
        ),
        (
            "hawk.tenant.ediscovery_roles",
            &["DirectoryObjectVersion", "ExchangeVersion"],
        ),
        ("hawk.tenant.impersonation", &["ExchangeVersion"]),
        ("hawk.tenant.entra_app_audit", &["UserId"]),
        (
            "hawk.user.converted_auth",
            &["KeepMeSignedIn", "UserAuthenticationMethod", "ZipCode"],
        ),
        (
            "hawk.user.mobile_devices",
            &[
                "AdminDisplayName",
                "DistinguishedName",
                "ExchangeObjectId",
                "ExchangeVersion",
                "Guid",
                "Id",
                "ObjectCategory",
                "ObjectClass",
                "OrganizationId",
                "OrganizationalUnitRoot",
                "OriginatingServer",
            ],
        ),
    ];
    let mut profiles = Vec::new();
    for c in [Collector::Hawk3, Collector::Hawk4] {
        let (dir, _) = r#gen("bec-aitm", c, PsEdition::Ps7);
        profiles.push((c, profile_dir(dir.path()).unwrap()));
    }
    for (artifact, columns) in EXPECTED {
        // An artifact the collector does not write at all (Hawk 4 dropped the tenant-level
        // `All_InboxRules`) is checked in the trees that do write it.
        let seen: Vec<&Collector> = profiles
            .iter()
            .filter(|(_, p)| p.artifacts.contains_key(*artifact))
            .map(|(c, _)| c)
            .collect();
        assert!(!seen.is_empty(), "{artifact} is in no generated tree");
        for (c, p) in &profiles {
            let Some(ap) = p.artifacts.get(*artifact) else {
                continue;
            };
            let header: std::collections::BTreeSet<&str> =
                ap.headers.keys().flatten().map(String::as_str).collect();
            let missing: Vec<&&str> = columns.iter().filter(|c| !header.contains(**c)).collect();
            assert!(missing.is_empty(), "{artifact} {c:?} lacks {missing:?}");
        }
    }
}

/// A real Hawk capture can hold the portal exports pulled beside it. `conform_real` compares
/// them when the generated side includes the portal collector (0 findings), and reports them
/// when it does not — the guard that keeps the comparison non-vacuous.
#[test]
fn conform_real_compares_portal_exports_beside_a_hawk_capture() {
    let (hawk_dir, _) = r#gen("bec-aitm", Collector::Hawk4, PsEdition::Ps7);
    let hawk = profile_dir(hawk_dir.path()).unwrap();
    let (portal_dir, _) = r#gen("bec-aitm", Collector::Portal, PsEdition::Ps7);
    let portal = profile_dir(portal_dir.path()).unwrap();

    // The stand-in real tree: the Hawk artifacts plus the portal exports beside them.
    let mut real = hawk.clone();
    for (artifact, ap) in &portal.artifacts {
        real.artifacts.insert(artifact.clone(), ap.clone());
    }

    let with_portal = vec![hawk.clone(), portal.clone()];
    let r = conform_real(&real, &with_portal);
    assert!(r.ok, "{}", r.to_text());

    let without_portal = vec![hawk];
    let r = conform_real(&real, &without_portal);
    assert!(!r.ok);
    assert!(
        r.findings.iter().any(|f| f.starts_with("portal.")),
        "{}",
        r.to_text()
    );
}

#[test]
fn a_real_mode_report_prints_no_values() {
    // A stand-in "real" tree: a generated one with recognisable values planted in it.
    let (dir, m) = r#gen("bec-aitm", Collector::Hawk4, PsEdition::Ps7);
    let root = dir.path().join(&m.root);
    let secret_user = "secret.person@contoso.example";
    let secret_ip = "203.0.113.99";
    std::fs::create_dir_all(root.join(secret_user)).unwrap();
    std::fs::write(
        root.join(secret_user).join("InboxRules_secret.person.csv"),
        format!("\"Name\",\"From\",\"{secret_user}\"\r\n\"Rule\",\"{secret_ip}\",\"x\"\r\n"),
    )
    .unwrap();
    let real = profile_dir(dir.path()).unwrap();
    let (gdir, _) = r#gen("bec-aitm", Collector::Hawk4, PsEdition::Ps51);
    let generated = vec![profile_dir(gdir.path()).unwrap()];
    let text = conform_real(&real, &generated).to_text();
    assert!(
        !text.contains(secret_user) && !text.contains(secret_ip) && !text.contains("secret"),
        "{text}"
    );
    assert!(text.contains("<masked>"));
}

/// The real captures' flattened / raw UAL files carry AuditData properties the generated
/// trees never did, so `--real` reported them as columns that are never generated. Each entry
/// is a property the generator already produces the operation for, per the Office 365
/// Management Activity API schema; the flattening itself is the collector's
/// `ConvertTo-FlatObject` (research hawk layouts §4.2), so a property in AuditData becomes the
/// column automatically.
///
/// Read from the JSON column union, not the CSV header: these are per-record-varying
/// flattened files, and `Export-Csv` writes only the first record's keys (research §2.3).
#[test]
fn the_flattened_ual_files_carry_the_captured_properties() {
    // (artifact, column): one representative column per AuditData property group.
    const EXPECTED: &[(&str, &str)] = &[
        // Token / app access context, on every Exchange record.
        ("hawk.user.raw_ual", "TokenObjectId"),
        ("hawk.user.raw_ual", "TokenTenantId"),
        ("hawk.user.raw_ual", "TokenType"),
        ("hawk.user.raw_ual", "HostAppId"),
        ("hawk.user.simple_ual", "AppAccessContext_UniqueTokenId"),
        ("hawk.user.simple_ual", "AppAccessContext_AADSessionId"),
        ("hawk.user.simple_ual", "AppAccessContext_IssuedAtTime"),
        ("hawk.user.simple_ual", "AppAccessContext_APIId"),
        ("hawk.user.simple_ual", "AppPoolName"),
        ("hawk.user.simple_ual", "CorrelationID"),
        ("hawk.user.simple_ual", "RequestId"),
        ("hawk.investigate_file", "AppAccessContext_UniqueTokenId"),
        ("hawk.investigate_file", "AppPoolName"),
        ("hawk.investigate_file", "TokenObjectId"),
        ("hawk.investigate_file", "TokenTenantId"),
        // ExchangeItem client detail and the item itself.
        ("hawk.user.raw_ual", "ClientInfoString"),
        ("hawk.user.raw_ual", "ClientProcessName"),
        ("hawk.user.raw_ual", "ClientVersion"),
        ("hawk.user.raw_ual", "ClientRequestId"),
        ("hawk.user.raw_ual", "SaveToSentItems"),
        ("hawk.user.raw_ual", "CrossMailboxOperation"),
        ("hawk.user.raw_ual", "ActorInfoString"),
        ("hawk.user.simple_ual", "Item_ImmutableId"),
        ("hawk.user.simple_ual", "Item_IsRecord"),
        ("hawk.user.simple_ual", "Item_ParentFolder_Name"),
        // MailItemsAccessed folder items.
        ("hawk.user.simple_ual", "AuthType"),
        ("hawk.user.simple_ual", "Folders_FolderItems_CreationTime"),
        ("hawk.user.simple_ual", "Folders_FolderItems_CreationTime_1"),
        ("hawk.user.simple_ual", "Folders_FolderItems_ImmutableId"),
        (
            "hawk.user.simple_ual",
            "Folders_FolderItems_InternetMessageId",
        ),
        ("hawk.user.simple_ual", "Folders_FolderItems_SizeInBytes"),
        ("hawk.user.simple_ual", "Folders_FolderItems_Subject"),
        // Exchange admin cmdlet parameters already logged, with their full parameter set.
        ("hawk.tenant.simple_ual", "Param_Force"),
        (
            "hawk.tenant.simple_ual",
            "Param_AlwaysDeleteOutlookRulesBlob",
        ),
        ("hawk.investigate_file", "Param_DeleteMessage"),
        ("hawk.investigate_file", "Param_MoveToFolder"),
        ("hawk.investigate_file", "Param_Force"),
        (
            "hawk.investigate_file",
            "Param_AlwaysDeleteOutlookRulesBlob",
        ),
        // The attacker's finance rule parameters reach the user Simple file.
        ("hawk.user.simple_ual", "Param_StopProcessingRules"),
        ("hawk.user.simple_ual", "Param_SubjectOrBodyContainsWords"),
        // Entra sign-in / AAD detail.
        ("hawk.user.simple_ual", "ExtendedProperties_Name"),
        ("hawk.user.simple_ual", "ExtendedProperties_Name_1"),
    ];
    // Column sets over the whole generated matrix.
    let mut seen: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        Default::default();
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            for ps in [PsEdition::Ps7, PsEdition::Ps51] {
                let dir = tempfile::tempdir().unwrap();
                let mut o = GenerateOptions::new(*c, 1);
                o.ps = ps;
                generate_to_dir(&load(name).unwrap(), &o, dir.path()).unwrap();
                for (art, ap) in &profile_dir(dir.path()).unwrap().artifacts {
                    for k in &ap.keys {
                        seen.entry(art.clone()).or_default().insert(k.clone());
                    }
                    for h in ap.headers.keys() {
                        seen.entry(art.clone())
                            .or_default()
                            .extend(h.iter().cloned());
                    }
                }
            }
        }
    }
    let missing: Vec<String> = EXPECTED
        .iter()
        .filter(|(art, col)| !seen.get(*art).is_some_and(|cols| cols.contains(*col)))
        .map(|(art, col)| format!("{art} {col}"))
        .collect();
    assert!(missing.is_empty(), "never generated: {missing:#?}");
}
