# extract test fixtures

- `xlswithmacro.xlsm` — a benign Excel workbook (.xlsm / OOXML) containing VBA
  macro modules. Used to prove the OOXML → vbaProject.bin → MS-OVBA decompress
  path yields cleartext macro source.

  Source: [Velocidex/oleparse](https://github.com/Velocidex/oleparse)
  `test_data/xlswithmacro.xlsm` (MIT License, © 2014 John William Davison).
  Vendored unchanged for offline testing.
