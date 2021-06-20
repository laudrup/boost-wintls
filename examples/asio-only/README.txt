WIP:

See commit details for verions required.
The first thing you will likely hit is problems including files. You will have edit the required directory for asio by hand.

This version uses a horrible system of using macros to define the proper includes
You need to define...
ASIO_STANDALONE
as it is almost certainly broken for boost right now