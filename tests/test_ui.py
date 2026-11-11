from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def test_sidebar_hover_override_has_higher_cascade_order():
    css=(ROOT/'static'/'css'/'style.css').read_text(encoding='utf-8')
    first_child_override=css.index('.sidebar nav a:first-child:not(.active)')
    nav_hover=css.rindex('.sidebar nav a:hover:not(.active)')
    assert nav_hover>first_child_override

def test_interactive_hover_and_reduced_motion_states_exist():
    css=(ROOT/'static'/'css'/'style.css').read_text(encoding='utf-8')
    assert '.button.primary:hover:not(:disabled)' in css
    assert '.main a:not(.button):hover' in css
    assert '.table-wrap tbody tr:hover' in css
    assert '@media(prefers-reduced-motion:reduce)' in css
