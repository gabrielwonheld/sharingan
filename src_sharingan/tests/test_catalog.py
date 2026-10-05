from view.catalog import HELP_SECTIONS, PHASES, command_names


def test_every_help_section_has_a_title_and_commands():
    assert HELP_SECTIONS
    for section in HELP_SECTIONS:
        assert section.title and section.commands


def test_command_names_splits_aliases_and_ignores_arguments():
    names = command_names()

    assert {'scan', 'exit', 'quit', 'phases', 'fases', 'info', 'crawl', 'findings'} <= names


def test_no_command_is_listed_twice_in_help():
    seen = []
    for section in HELP_SECTIONS:
        for syntax, _ in section.commands:
            seen.append(syntax)

    assert len(seen) == len(set(seen))


def test_phases_have_the_fields_the_console_renders():
    assert [p.key for p in PHASES] == ['recon', 'scan', 'crawl', 'fuzz']
    for phase in PHASES:
        assert phase.title and phase.traffic and phase.run_with and phase.tools
        assert phase.results and phase.not_run_hint


def test_every_registered_console_command_is_documented_in_help(mocker):
    """Guards against a new command being added to the console but forgotten in
    `help`/`phases` (the help used to be a hand-maintained flat list)."""
    mocker.patch('view.console.get_session')
    mocker.patch('view.console.init_db')
    mocker.patch('view.console.PromptSession')
    from view.console import InteractiveConsole

    console = InteractiveConsole()

    assert set(console.cmds) <= command_names()
    assert command_names() <= set(console.cmds)
