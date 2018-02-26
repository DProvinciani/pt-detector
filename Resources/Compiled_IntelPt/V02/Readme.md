This version implements a fix to suport the Spectre&Meltdown windows patch.
The path includes a new mechanism to work with the directory table. Now there are two
base addresses, one is the DirectoryTableBase and the other the UserDirectoryTableBase.

nt!_KPROCESS
+0x000 Header : _DISPATCHER_HEADER
+0x018 ProfileListHead : _LIST_ENTRY
+0x028 DirectoryTableBase : Uint8B
+0x030 ThreadListHead : _LIST_ENTRY
+0x040 ProcessLock : Uint4B
+0x044 ProcessTimerDelay : Uint4B
+0x048 DeepFreezeStartTime : Uint8B
+0x050 Affinity : _KAFFINITY_EX
+0x0f8 ReadyListHead : _LIST_ENTRY
+0x108 SwapListEntry : _SINGLE_LIST_ENTRY
+0x110 ActiveProcessors : _KAFFINITY_EX
+0x1b8 AutoAlignment : Pos 0, 1 Bit
+0x1b8 DisableBoost : Pos 1, 1 Bit
+0x1b8 DisableQuantum : Pos 2, 1 Bit
+0x1b8 DeepFreeze : Pos 3, 1 Bit
+0x1b8 TimerVirtualization : Pos 4, 1 Bit
+0x1b8 CheckStackExtents : Pos 5, 1 Bit
+0x1b8 PpmPolicy : Pos 6, 3 Bits
+0x1b8 ActiveGroupsMask : Pos 9, 20 Bits
+0x1b8 ReservedFlags : Pos 29, 3 Bits
+0x1b8 ProcessFlags : Int4B
+0x1bc BasePriority : Char
+0x1bd QuantumReset : Char
+0x1be Visited : UChar
+0x1bf Flags : _KEXECUTE_OPTIONS
+0x1c0 ThreadSeed : [20] Uint4B
+0x210 IdealNode : [20] Uint2B
+0x238 IdealGlobalNode : Uint2B
+0x23a Spare1 : Uint2B
+0x23c StackCount : _KSTACK_COUNT
+0x240 ProcessListEntry : _LIST_ENTRY
+0x250 CycleTime : Uint8B
+0x258 ContextSwitches : Uint8B
+0x260 SchedulingGroup : Ptr64 _KSCHEDULING_GROUP
+0x268 FreezeCount : Uint4B
+0x26c KernelTime : Uint4B
+0x270 UserTime : Uint4B
+0x274 ReadyTime : Uint4B
+0x278 UserDirectoryTableBase : Uint8B
+0x280 AddressPolicy : UChar
+0x281 Spare2 : [71] UChar
+0x2c8 InstrumentationCallback : Ptr64 Void
+0x2d0 SecureState :