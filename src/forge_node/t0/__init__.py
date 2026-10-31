"""T0 (read-only) layer shared by the agent and the `ro-probe` op class (Design 4.1, 4.4, 10.4). Everything that touches the host goes through one guarded path:
engine.T0Engine.execute() -> runner.ReadOnlyRunner / fsread.Fs. There is no optional guard input anywhere in this package."""
