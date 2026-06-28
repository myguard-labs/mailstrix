/*
  Behavioral-score tier -- olevba "weight of evidence" aggregate.

  Every LOW-confidence structural marker Mailstrix emits (OLEID-*, OLETIMES-*,
  DIGITAL-SIGNATURE, ENCRYPTION-RC4/AES, DOC-SECURITY, OLE2-EXTRA-DATA,
  USERFORM/DOCPROPS-STRINGS, DEFAULTPW-DECRYPTED) is benign on its own -- a real
  document can legitimately carry any single one, so each is scored <=25 by its
  own rule (oleid_indicators.yara). olevba's analysis treats the CO-OCCURRENCE of
  several independent weak indicators as suspicious even when no single strong
  rule fires.

  extract.joinBehaviorScore (internal/extract/markers.go) counts the DISTINCT
  weak-marker classes present in one document and, when >=3 co-occur, emits one
  aggregate marker stream "MALDOC-BEHAVIOR-SCORE n=<count>\n<class>...". This
  rule scores that aggregate. The literal prefix is emitted only by Mailstrix, so
  matching it is zero-FP by construction; the threshold (3 distinct classes) was
  chosen because the 761-sample parity corpus surfaced no benign document tripping
  three independent structural indicators at once. This is a NOVEL-maldoc backstop
  (the corpus showed the marker+rule set already mirrors olevba with zero gap),
  not a tuned detector.

  Two tiers:
    * 3-4 classes -> heuristic suspicious  (score 30) -> STRIX_SUSPICIOUS
    * 5+ classes  -> stronger              (score 60) -> still routed via tags,
      operator-tunable in groups.conf.

  Tagged `suspicious heuristic` so mailstrix.lua classify() routes them to
  STRIX_SUSPICIOUS (operator-tunable).
  Reference: https://github.com/decalage2/oletools/wiki/olevba
*/

rule Maldoc_Behavior_Score : maldoc heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "Several independent low-confidence structural markers co-occur (olevba weight-of-evidence)"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "30"
    strings:
        $marker = "MALDOC-BEHAVIOR-SCORE n=" ascii
    condition:
        filesize < 64MB and $marker
}

rule Maldoc_Behavior_Score_High : maldoc heuristic suspicious marker
{
    meta:
        author      = "mailstrix"
        description = "Five or more independent low-confidence structural markers co-occur -- strong weight-of-evidence"
        reference   = "https://github.com/decalage2/oletools/wiki/olevba"
        score       = "60"
    strings:
        // n= is a one- or two-digit count; 5..9 or any two-digit value (>=10).
        $n5    = "MALDOC-BEHAVIOR-SCORE n=5" ascii
        $n6    = "MALDOC-BEHAVIOR-SCORE n=6" ascii
        $n7    = "MALDOC-BEHAVIOR-SCORE n=7" ascii
        $n8    = "MALDOC-BEHAVIOR-SCORE n=8" ascii
        $n9    = "MALDOC-BEHAVIOR-SCORE n=9" ascii
        // two-digit count (10..16): "n=1" followed by another digit.
        $n1x_0 = "MALDOC-BEHAVIOR-SCORE n=10" ascii
        $n1x_1 = "MALDOC-BEHAVIOR-SCORE n=11" ascii
        $n1x_2 = "MALDOC-BEHAVIOR-SCORE n=12" ascii
        $n1x_3 = "MALDOC-BEHAVIOR-SCORE n=13" ascii
        $n1x_4 = "MALDOC-BEHAVIOR-SCORE n=14" ascii
        $n1x_5 = "MALDOC-BEHAVIOR-SCORE n=15" ascii
        $n1x_6 = "MALDOC-BEHAVIOR-SCORE n=16" ascii
    condition:
        filesize < 64MB and any of them
}
