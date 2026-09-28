#[path = "common/synth.rs"]
mod synth;

use sparrow_synth::options::PsEdition;
use synth::*;

#[test]
fn exchange_and_graph_rules_load_with_parsed_recipients_and_folders() {
    for ps in [PsEdition::Ps7, PsEdition::Ps51] {
        let g = builtin("bec-aitm", ps);
        // The victim's hiding rule: name ".", RSS Feeds, finance words.
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE name = '.' AND move_to_folder = 'RSS Feeds' AND source = 'exo'"
            ),
            1
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE name = '.' AND source = 'graph'"
            ),
            1
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE list_contains(forward_to, 'invoices@exfil-mail.test') AND source = 'exo'"
            ),
            1
        );
        assert!(
            count(
                &g.case,
                "SELECT count(*) FROM inbox_rules WHERE description LIKE 'If the message:%'"
            ) >= 1
        );
        assert_eq!(
            count(
                &g.case,
                "SELECT count(*) FROM transport_rules WHERE name = 'Journal copy'"
            ),
            1
        );
        check_green(&g);
    }
}
