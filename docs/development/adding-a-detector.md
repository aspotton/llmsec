# Adding a detector

A detector must:

1. declare a `DetectorSpec`;
2. identify supported `Stage` values;
3. operate over shared immutable `ContentViews`;
4. return `Finding` objects;
5. remain bounded and local unless explicitly documented as an optional deep detector;
6. include tests and known limitations.

Do not put block/allow decisions in detector code. That belongs in policy.
