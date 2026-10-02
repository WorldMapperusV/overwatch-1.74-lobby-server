"""Statescript on ch1: frames that put graph instances on an entity and set their states and
variables. The client runs the graphs; the server says which instances exist and what is on.

Read in the client (runtime-decrypted 1.74 image; RVAs are ASLR-independent):
- The chunk reader is Overwatch.exe+0x996450. The owner-frame instance-list reader is +0xA0E1D0,
  reached by the higher-level apply routine +0xA0E3C0; a new instance descriptor is read at +0xA0C510
  and its graph/parent/reference descriptor body at +0xA0ADC0.
- A chunk is `w_u32 first | w_var span | bit fragmented | w_var size in bits | payload`. first 0 is a
  full frame. The client keeps the highest `last` (first + span) it applied and drops chunks at or
  below it, so an unchanged chunk can be sent again safely.
- The payload starts `bit lead | bit H`; with H (an owner frame): `bit C | w_var CmFD`, and in a delta
  also `w_var LBSS` (the body's length). An owner frame is skipped unless its CmFD is larger than the
  last one (unsigned, so 0 never applies).
- A full frame lists the instances (w_u16 index steps, each with a descriptor: 16 bits graph, bit other
  entity, bit flag, bit parent -> w_var parent instance and w_var parent STATE index, bit references),
  then the entity's variables, then per instance its variables, one bit per state, and in an owner
  frame its event list; then the frame's event list. It destroys the network instances it does not
  list and first clears the variables the network set, so every full frame carries everything.
- In an owner frame the states are the graph's m_states minus the client-only and server-only ones.
  A SubScript state that is on carries its child's instance id (w_u16) and a bit.
- Instances the server makes never run their own Entry nodes (only client-only ones run), so the
  server sends what those would have done: the states that are on and the variables.
"""

import struct
from dataclasses import dataclass, field

from ow174.game.bits import BitWriter
from ow174.game.world import EntityUpdate


@dataclass(frozen=True)
class Graph:
    index: int  # the 01B graph's 16-bit index
    owner_states: int  # state bits in an owner frame
    sync_vars: int  # per-instance variable presence bits


# From the graph data (the counts match what worked in ProCore's live tests).
CONTROLLER = Graph(0x13C1, 43, 12)  # the player's controller in the Practice Range mode
PVP_CONTROLLER = Graph(0x0C90, 118, 29)  # the controller of both teams in the PvP modes
HUD = Graph(0x20E4, 1, 0)  # 13C1's weapon and ability HUD (0C90 starts its own)
HERO_SELECT_HOST = Graph(0x288A, 6, 0)
HERO_SELECT = Graph(0x288B, 30, 4)  # presents the hero select screen 008C.05A
TEAM_ENTRY = Graph(0x288D, 0, 0)  # client-only: posts its entity to the local player's team list

# Soldier: 76's body definition 03CF starts these nine graphs, in this definition order.  The
# second number is the owner-frame state-bit count; the third is the count of instance-scoped sync
# variables (not the graph's padded sync table length).  Keep the complete set together in any body
# owner full-frame probe: the client treats an omitted network instance as destroyed.
SOLDIER_BODY_GRAPHS = (
    Graph(0x0033, 12, 4),
    Graph(0x004B, 39, 4),
    Graph(0x0043, 27, 7),
    Graph(0x0251, 3, 0),
    Graph(0x0255, 31, 9),
    Graph(0x0257, 21, 6),
    Graph(0x0259, 44, 7),
    Graph(0x091B, 2, 0),
    Graph(0x08B6, 13, 2),
)

# 004B's creation entry starts five SubScripts simultaneously.  Their parent STATE indices are
# 0, 3, 5, 10 and 18 respectively (descriptor parents use state indices, not owner-bit indices).
# In particular 01CF is the child containing several UX presenters and the network sync for v17906,
# one of 20E4's HUD inputs.  This is why probing 0257 alone could never reconstruct the ability HUD.
SOLDIER_004B_INITIAL_CHILDREN = (
    (0, Graph(0x01C7, 44, 1)),
    (3, Graph(0x01CF, 41, 22)),
    (5, Graph(0x02C5, 13, 4)),
    (10, Graph(0x0B8B, 4, 0)),
    (18, Graph(0x0C7D, 0, 0)),
)

# Soldier startup reconstruction from the extracted 1.74 graphs and the client reader.
# +0xA0E1D0 accumulates the transmitted u16 Inst steps into an instance id, looks that id up, and if
# it is absent allocates a slot and passes the transmitted id unchanged to +0xA0C510.  Therefore the
# ids are SERVER-ASSIGNED; they do not have to match hidden retail allocation ids.  Parent descriptors
# merely have to refer to ids in the same coherent topology.  This removes the last reason to capture
# retail instance ids before constructing a full frame.
#
# Every non-client/non-server STUStatescriptEntry is a creation entry.  Some graphs deliberately have
# more than one; all of their immediate action chains run.  Stop traversal when a state is entered --
# following that state's output plugs would incorrectly include later transitions.
SOLDIER_INITIAL_OWNER_BITS = {
    0x0033: (8, 9, 10),
    0x004B: (0, 3, 5, 10, 12, 13, 14, 15, 18, 19, 20, 22, 23, 24, 25, 27, 31, 33),
    0x0043: (6, 15, 21), 0x0251: (0, 1),
    0x0255: (2, 4, 6, 7, 8, 16, 17, 18, 22, 28),
    0x0257: (7, 11, 12, 13, 18), 0x0259: (0, 15, 17),
    0x091B: (0,), 0x08B6: (0, 1, 4, 7, 9, 10),
}

# Active SubScripts reveal three children that were missing from the first topology pass: 004B state
# 24 -> 1463, 08B6 state 4 -> 0BF8, and 01CF state 32 -> 0E8F.  None of those three starts another
# SubScript, so this closes the recursively reachable creation topology for Soldier's body roots.
SOLDIER_INITIAL_CHILDREN = (
    (0x004B, 0, 0x01C7), (0x004B, 3, 0x01CF), (0x004B, 5, 0x02C5),
    (0x004B, 10, 0x0B8B), (0x004B, 18, 0x0C7D), (0x004B, 24, 0x1463),
    (0x08B6, 4, 0x0BF8), (0x01CF, 32, 0x0E8F),
)
SOLDIER_CHILD_GRAPHS = {
    0x01C7: Graph(0x01C7, 44, 1), 0x01CF: Graph(0x01CF, 41, 22),
    0x02C5: Graph(0x02C5, 13, 4), 0x0B8B: Graph(0x0B8B, 4, 0),
    0x0C7D: Graph(0x0C7D, 0, 0), 0x1463: Graph(0x1463, 2, 0),
    0x0BF8: Graph(0x0BF8, 6, 0), 0x0E8F: Graph(0x0E8F, 7, 3),
}
SOLDIER_INITIAL_CHILD_OWNER_BITS = {
    0x01C7: (4, 7, 10, 12, 13, 15, 16, 18, 21, 23, 24, 29, 35, 36, 38, 39, 40),
    0x01CF: (4, 6, 8, 11, 13, 14, 17, 20, 22, 23, 24, 25, 32, 33),
    0x02C5: (6,), 0x0B8B: (0,), 0x0C7D: (), 0x1463: (0,), 0x0BF8: (0,), 0x0E8F: (5,),
}

# 03CF also creates definition-level weapon manager 0015 and primary weapon 0254.  Their graph sizes
# are owner-state counts (client/server-only states removed) and compact INSTANCE sync-var counts.
SOLDIER_WEAPON_MANAGER = Graph(0x0015, 35, 1)
SOLDIER_PRIMARY_WEAPON = Graph(0x0254, 81, 23)
SOLDIER_WEAPON_INITIAL_OWNER_BITS = {0x0015: (11, 27, 28, 29), 0x0254: (0, 31, 55, 60, 62, 76)}

# Known literal Entry writes that a server-created instance must reproduce because its server Entry
# actions do not execute locally: 0033 entity v32350=.3; 004B entity v14676=true; 0043 instance
# v476=30, v215=.5, v1258=0, v1257=1; 0255 instance v1002=.5, v636=.3; 01CF instance v7044=true,
# v8831=true; 01C7 entity v31296=1.  0254 initializes v476=20, v581=1.5, v6884=.511, v6885=.1,
# v229=0, v230=0, v1769=100, v1770=100 and derives v198/v53/v7185.  0015's v9526/v9573 writes are
# self/default expressions rather than independent constants.  The remaining implementation task is
# now mechanical: assign ids to these 19 instances, attach the eight children above, put child ids in
# the corresponding SubScript state payloads, and serialize the complete authoritative body frame.

class Value:
    tag: int

    def write(self, out: BitWriter) -> None:
        raise NotImplementedError


@dataclass(frozen=True)
class Bool(Value):
    value: bool

    def write(self, out: BitWriter) -> None:
        out.bits(0, 4)
        out.bit(self.value)


@dataclass(frozen=True)
class Int(Value):
    value: int

    def write(self, out: BitWriter) -> None:
        out.bits(4, 4)
        out.bits(self.value & 0xFFFFFFFF, 32)


@dataclass(frozen=True)
class Float(Value):
    value: float

    def write(self, out: BitWriter) -> None:
        out.bits(8, 4)
        out.bits(struct.unpack("<I", struct.pack("<f", self.value))[0], 32)


@dataclass(frozen=True)
class Asset(Value):
    """A GUID read as an asset (a hero, for example): its type bits and its low 32 bits."""

    guid: int

    def write(self, out: BitWriter) -> None:
        out.bits(9, 4)
        out.bit(1)
        out.bits(self.guid >> 48, 16)
        if self.guid >> 48:
            out.w_var(self.guid & 0xFFFFFFFF)


@dataclass(frozen=True)
class Entity(Value):
    entity: int

    def write(self, out: BitWriter) -> None:
        out.bits(13, 4)
        out.bit(1)
        out.bits(self.entity & 0xFFFFFFFF, 32)


def write_variable(out: BitWriter, value: Value) -> None:
    value.write(out)
    out.bit(0)  # no bindings


def subscript(child: int) -> BitWriter:
    """The payload of a SubScript state that is on: its child instance."""
    out = BitWriter()
    out.w_u16(child)
    out.bit(0)
    return out


@dataclass
class Instance:
    index: int
    graph: Graph
    parent: tuple[int, int] | None = None  # (parent instance, the parent graph's state index)
    presence: dict[int, Value] = field(default_factory=dict)  # presence bit -> value
    extra: dict[int, Value] = field(default_factory=dict)  # variable id -> value
    active: dict[int, BitWriter | None] = field(default_factory=dict)  # owner state bit -> payload


def _descriptor(out: BitWriter, instance: Instance) -> None:
    out.bits(instance.graph.index, 16)
    out.bit(0)  # the instance lives on this entity
    out.bit(0)  # flag
    if instance.parent is None:
        out.bit(0)
    else:
        out.bit(1)
        out.w_var(instance.parent[0])
        out.w_var(instance.parent[1])
    out.bit(0)  # no references


def _variables(out: BitWriter, variables: dict[int, Value]) -> None:
    for number, value in variables.items():
        out.w_var(number)
        write_variable(out, value)
    out.w_var(0)


def owner_full_frame(cmfd: int, instances: list[Instance], entity_vars: dict[int, Value]) -> BitWriter:
    """An owner (H=1) full frame. `cmfd` must be larger than any CmFD sent to this entity before."""
    if cmfd < 1:
        raise ValueError("CmFD 0 is always stale")
    out = BitWriter()
    out.bit(0)  # lead
    out.bit(1)  # H
    out.bit(0)  # C
    out.w_var(cmfd)
    last = 0
    for instance in sorted(instances, key=lambda item: item.index):
        out.w_u16(instance.index - last)
        last = instance.index
        _descriptor(out, instance)
    out.w_u16(0)
    if entity_vars:
        out.bit(1)
        _variables(out, entity_vars)
    else:
        out.bit(0)
    for instance in sorted(instances, key=lambda item: item.index):
        for bit in range(instance.graph.sync_vars):
            value = instance.presence.get(bit)
            out.bit(value is not None)
            if value is not None:
                write_variable(out, value)
        if instance.extra:
            out.bit(1)
            _variables(out, instance.extra)
        else:
            out.bit(0)
        for bit in range(instance.graph.owner_states):
            on = bit in instance.active
            out.bit(on)
            payload = instance.active.get(bit)
            if on and payload is not None:
                out.append(payload)
        out.bits(0b11, 2)  # the instance's event list ends (code 3)
    out.bits(0, 2)  # the frame's event lists: none
    return out




def soldier_body_frame(cmfd: int) -> BitWriter:
    """Soldier: 76's complete initial owner frame.

    Runtime instance ids are ours to assign.  Roots are 1..9, recursively-created SubScripts 10..17,
    then the definition-level weapon manager and primary weapon are 18 and 19.  Parent descriptors
    use the parent's STATE index; the active-state dictionary uses owner-frame bit indices.
    """
    roots = {graph.index: i + 1 for i, graph in enumerate(SOLDIER_BODY_GRAPHS)}
    instances = [
        Instance(
            roots[graph.index],
            graph,
            active={bit: None for bit in SOLDIER_INITIAL_OWNER_BITS[graph.index]},
        )
        for graph in SOLDIER_BODY_GRAPHS
    ]

    child_ids: dict[int, int] = {}
    next_id = 10
    for parent_graph, parent_state, child_graph in SOLDIER_INITIAL_CHILDREN:
        child_ids[child_graph] = next_id
        next_id += 1

    def instance_id(graph: int) -> int:
        return roots.get(graph) or child_ids[graph]

    # The SubScript state's serialized owner bit can differ from its graph state index.  Of Soldier's
    # startup children only 01CF state 32 is shifted by filtered client-only states: state 32 -> bit 22.
    child_owner_bit = {(0x01CF, 32): 22}
    for parent_graph, parent_state, child_graph in SOLDIER_INITIAL_CHILDREN:
        parent_id = instance_id(parent_graph)
        child_id = child_ids[child_graph]
        parent = next(item for item in instances if item.index == parent_id)
        bit = child_owner_bit.get((parent_graph, parent_state), parent_state)
        parent.active[bit] = subscript(child_id)
        instances.append(
            Instance(
                child_id,
                SOLDIER_CHILD_GRAPHS[child_graph],
                parent=(parent_id, parent_state),
                active={bit: None for bit in SOLDIER_INITIAL_CHILD_OWNER_BITS[child_graph]},
            )
        )

    manager = Instance(
        18,
        SOLDIER_WEAPON_MANAGER,
        active={bit: None for bit in SOLDIER_WEAPON_INITIAL_OWNER_BITS[0x0015]},
    )
    weapon = Instance(
        19,
        SOLDIER_PRIMARY_WEAPON,
        active={bit: None for bit in SOLDIER_WEAPON_INITIAL_OWNER_BITS[0x0254]},
    )
    instances += [manager, weapon]

    # Literal server Entry writes.  Send them by variable id rather than guessing compact presence
    # slots; the full-frame variable list accepts instance variables by id.
    by_graph = {item.graph.index: item for item in instances}
    by_graph[0x0043].extra.update({476: Int(30), 215: Float(.5), 1258: Int(0), 1257: Int(1)})
    by_graph[0x0255].extra.update({1002: Float(.5), 636: Float(.3)})
    by_graph[0x01CF].extra.update({7044: Bool(True), 8831: Bool(True)})
    weapon.extra.update({
        476: Int(20), 581: Float(1.5), 6884: Float(.511), 6885: Float(.1),
        229: Int(0), 230: Int(0), 1769: Int(100), 1770: Int(100),
    })
    entity_vars = {32350: Float(.3), 14676: Bool(True), 31296: Int(1)}
    return owner_full_frame(cmfd, instances, entity_vars)


def variables_frame(entity_vars: dict[int, Value]) -> BitWriter:
    """A plain (H=0) full frame with no instances, only entity variables: how an entity without
    graphs of its own, such as the game mode entity, gets values that other graphs read from it."""
    out = BitWriter()
    out.bit(0)  # lead
    out.bit(0)  # H
    out.w_u16(0)  # no instances
    if entity_vars:
        out.bit(1)
        _variables(out, entity_vars)
    else:
        out.bit(0)
    out.bits(0, 2)  # the frame's event lists: none
    return out


def owner_ack(cmfd: int) -> BitWriter:
    """An owner delta that only moves CmFD on: the client then replays fewer of its own commands when it
    rolls its prediction back."""
    out = BitWriter()
    out.bit(0)  # lead
    out.bit(1)  # H
    out.bit(0)  # C
    out.w_var(cmfd)
    out.w_var(7)  # LBSS: the body below, up to the "more" bit
    out.w_u16(0)  # no instances
    out.bit(0)  # no entity variables
    out.bit(0)  # no instance events
    out.bit(0)  # no more sub-frames
    out.bits(0, 2)  # no frame events
    return out


def chunk(payload: BitWriter, first: int, span: int) -> BitWriter:
    out = BitWriter()
    out.w_u32(first)
    out.w_var(span)
    out.bit(0)  # not fragmented
    out.w_var(payload.count)
    out.append(payload)
    return out


class Stream:
    """One entity's statescript as one client gets it: the frame numbers of the chunks sent and
    delivered, and the last CmFD. The client applies a chunk only when its last frame is new to it and
    drops a queued chunk whose range a newer chunk covers, so every chunk gets the next number and a
    chunk with data must arrive before an ack-only delta may cover it."""

    def __init__(self, entity: int) -> None:
        self.entity = entity
        self.last = 0  # the last frame number sent
        self.delivered = 0  # the highest last frame the client has
        self.data_last = 0  # the last chunk that carries data, not only an ack
        self.cmfd = 0
        self.next_ack = 0.0  # when the next ack-only delta may go

    def next_cmfd(self, newest: int) -> int:
        """The client skips an owner frame whose CmFD is not larger than the last one."""
        self.cmfd = max(newest, self.cmfd + 1)
        return self.cmfd

    @property
    def data_in_flight(self) -> bool:
        return self.delivered < self.data_last

    def full_frame(self, frame: BitWriter) -> EntityUpdate:
        """A full frame; sent again unchanged when its datagram is lost."""
        self.last += 1
        self.data_last = self.last
        return self._update(chunk(frame, 0, self.last), resend=True)

    def ack_delta(self, frame: BitWriter) -> EntityUpdate:
        """A delta that only moves CmFD on. A later one covers it, so a lost one is not sent again."""
        first = self.delivered + 1
        self.last += 1
        return self._update(chunk(frame, first, self.last - first), resend=False)

    def arrived(self, last: int) -> None:
        self.delivered = max(self.delivered, last)

    def _update(self, data: BitWriter, resend: bool) -> EntityUpdate:
        update = EntityUpdate(self.entity, chunk=data)
        update.chunk_last = self.last
        update.stream = self
        update.resend = resend
        return update
