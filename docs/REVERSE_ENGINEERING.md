# Reverse Engineering w/Ghidra

Here I will note all the knowledge gained when Reverse Engineering the libPVZ2.so

> ⚠️ IMPORTANT: Currently the version is 13.5.1 AArch64 (64-bit) at time of this document, so the information might differ on other version of the game!

## .so Structure Info

The program sectors in the .so contain the following data:
- the VTables are stored in `.data.rel.ro`
- the Functions are stored in `.text`
- the INIT/FINI Function pointers are stored in `.init_array` resp. `.fini_array`
- the Strings with lots of cross-references are stored in `.rodata`
- the ? are stored in `.data`

## VTables

These are important structures, as they provide cross-references and function pointers to functions from different classes.
Most VTables are cross-references in the Constructor `Class::Class` and Destructor `Class::~Class` of a class, since it's the first pointer parameter of a class.

Example in the Ghidra disassembler
```
Sexy::RtClass::RtClass_VTable                     XREF[2]:     RtClass:0282b3a0(*), 
                                                               ~RtClass:0282c008(*)  
03147f20 18 b2 82        addr       FUN_X
         02 00 00 
         00 00
```

> Tip: Sometimes the destructor `Class::~Class` is the 3rd function pointer in a VTable.

### Type Info

In the VTables of a class, above the VTable there's a pointer to the typeInfo of the Class, which basically helps with finding the inheritance and namespace.

Example in the Ghidra disassembler
```
03148398 f8 84 14        addr       Sexy::WidgetContainer::typeInfo                  = 032f30c0
         03 00 00 
         00 00
                     Sexy::WidgetContainer::WidgetContainerVTable    XREF[4]:     new:0282e3c0(*), 
                                                                                  WidgetContainer:0282e5dc(*), 
                                                                                  ~WidgetContainer:0282e630(*), 
                                                                                  destroy:0282e6a8(*)  
031483a0 30 e3 82        WidgetCo...
         02 00 00 
         00 00 f0 ...
                     Sexy::WidgetContainer::typeInfo                 XREF[3]:     03144910(*), 03146998(*), 
                                                                                  03148398(*)  
031484f8 c0 30 2f        pointer    __cxxabiv1::__si_class_type_info::vtable+0x10    = ??
         03 00 00 
         00 00
03148500 da 1b ae        addr       s_N4Sexy15WidgetContainerE_00ae1bda              = "N4Sexy15WidgetContainerE"
         00 00 00 
         00 00
03148508 68 7f 14        addr       Sexy::RtObject::typeInfo                         = 032f30b8
         03 00 00 
         00 00
```

`N4Sexy15WidgetContainerE` would mean this class is the `Sexy::WidgetContainer`
Then under the `s_N4Sexy15WidgetContainerE_00ae1bda` we can see the super/parent type info (can be just a `PTR_vtable` if not named). Basically this would translate to this

```cpp
namespace Sexy;
public WidgetContainer : RtObject;
```

> Tip: Ghidra doesn't analyse this correctly so it will show just the reference under `__cxxabiv1::__si_class_type_info::vtable+0x10` and you have to press P or Data->pointer

## Thunk Functions

## Classes

### Constructor Function

In a constructor function, `*self` is the class definition pointer!
This can give the number of fields and their sizes.

Example in Ghidra decompiler
```cpp
void Sexy::RtClass::RtClass(RtClass *self)
  ...
  self->vtable = &RtClass_VTable; // If type is undefined: *self = &RtClass_VTable
  self->field_2 = 0;
  self->field_3 = 0;
  self->field_4 = 0;
  FUN_026e18d4(&self->field_5);
  self->field_7 = 0;
  self->field_6 = 0;
  self->field_9 = 0;
  self->field_8 = 0;
  ...
}
```

### Initializer (First VTable function pointer)

In the VTable of a Class, the first function pointer leads to the initialize function.

Example in Ghidra decompiler
```cpp
RtClass * Sexy::RtClass::init(void) {
  RtClass *self;
  RtClass *super;
  
  if (instance == (RtClass *)0x0) {
    self = operator.new(0x48);
    RtClass(self);
    instance = self;
    if (DAT_032c52c0 == (RtClass *)0x0) {
      super = operator.new(0x48);
      RtClass(super);
      DAT_032c52c0 = super;
      (**(code **)(super->vtable + 0x40))(super, "RtObject", 0, RtObject::new);
    }
    (**(code **)(self->vtable + 0x40))(self, "RtClass", DAT_032c52c0, new);
    FUN_0282b21c();
  }
  return instance;
}
```

Here we can already find useful information such as:
- size `plVar1 = operator.new(0x48);`
- constructor/s (can contain multiple constructors based on inheritance) `RtClass();`
- the class instance `return DAT_032c52c8;`
- parent Class `plVar2`
- new function `FUN_0282b024`
- registerClass function `self->vtable + 0x40` which is the ninth function in the VTable
- registerFields function `FUN_0282b21c();`

> Note: The initializer can be a thunk function!

### Destroy Function (Fourth VTable function pointer)

In the VTable of a Class, the fourth function pointer leads to the destructor.

Example in Ghidra decompiler
```cpp
void Sexy::RtClass::destroy(RtClass *self) {
  ~RtClass(self);
  operator.delete(self,0x48);
  return;
}
```

Here we can mostly just see the destructor being called and then `operator.delete`.

### Type check (Fifth VTable function pointer)

In the VTable of a Class, the fifth function pointer leads to a type check function.

Example in Ghidra decompiler
```cpp
void Sexy::RtClass::isType(undefined8 *param_1, undefined8 param_2) {
  long *plVar1;

  plVar1 = (long *)(**(code **)*param_1)();
  (**(code **)(*plVar1 + 0x38))(plVar1,param_2);
  return;
}
```

Here we can find the `derives` function `*plVar1 + 0x38` basically the 8th function in the VTable.

### Derives (Eigth VTable function pointer)

In the VTable of a Class, the fifth function pointer leads to a derives function.

Example in Ghidra decompiler
```cpp
bool Sexy::RtClass::derives(RtClass *self, RtClass *target) {
  if (target == (RtClass *)0x0) {
    return false;
  }
  if (self != target) {
    do {
      self = self->super;
      if (self == target) {
        return self != (RtClass *)0x0;
      }
    } while (self != (RtClass *)0x0);
    return false;
  }
  return true;
}
```

### Register Class (Ninth VTable function pointer)

In the VTable of a Class, the fifth function pointer leads to a class register function.

Example in Ghidra decompiler
```cpp
void Sexy::RtClass::registerClass(RtClass *self, char *name, RtClass *super, undefined *factory) {
  ...
  self->name = name;
  self->super = super;
  self->factory = factory;
  ...
}
```