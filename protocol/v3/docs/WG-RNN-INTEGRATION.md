# WG-RNN Integration Profile

WG-RNN uses witnessed recurrent admission rather than treating every observation as state truth. DBP therefore transports observations and witness references separately from mutation authority.

Important alignment rules:

- temporal witnesses preserve source time, observation time, uncertainty and source reference;
- sequence labels are one-origin;
- a blocked witness cannot mutate recurrent state;
- gaps, chronology and predecessor receipt IDs remain explicit;
- categorical observations are not silently promoted into numeric evidence;
- observer/evidence outputs can be carried as evidence references without granting them authority;
- Runtime/Router/Memory traffic should use independent streams so slow bulk evidence cannot head-of-line-block control or live source probes.

Suggested lanes: source observation, observer result, witness-gate receipt, router plan, runtime execution receipt, memory commit proposal and evidence/object transfer. Memory commits remain gated application actions rather than transport side effects.
