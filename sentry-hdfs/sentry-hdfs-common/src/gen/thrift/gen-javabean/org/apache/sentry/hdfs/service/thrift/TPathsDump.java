/**
 * Autogenerated by Thrift Compiler (0.9.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
package org.apache.sentry.hdfs.service.thrift;

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.thrift.scheme.IScheme;
import org.apache.thrift.scheme.SchemeFactory;
import org.apache.thrift.scheme.StandardScheme;

import org.apache.thrift.scheme.TupleScheme;
import org.apache.thrift.protocol.TTupleProtocol;
import org.apache.thrift.protocol.TProtocolException;
import org.apache.thrift.EncodingUtils;
import org.apache.thrift.TException;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.EnumMap;
import java.util.Set;
import java.util.HashSet;
import java.util.EnumSet;
import java.util.Collections;
import java.util.BitSet;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TPathsDump implements org.apache.thrift.TBase<TPathsDump, TPathsDump._Fields>, java.io.Serializable, Cloneable {
  private static final org.apache.thrift.protocol.TStruct STRUCT_DESC = new org.apache.thrift.protocol.TStruct("TPathsDump");

  private static final org.apache.thrift.protocol.TField ROOT_ID_FIELD_DESC = new org.apache.thrift.protocol.TField("rootId", org.apache.thrift.protocol.TType.I32, (short)1);
  private static final org.apache.thrift.protocol.TField NODE_MAP_FIELD_DESC = new org.apache.thrift.protocol.TField("nodeMap", org.apache.thrift.protocol.TType.MAP, (short)2);

  private static final Map<Class<? extends IScheme>, SchemeFactory> schemes = new HashMap<Class<? extends IScheme>, SchemeFactory>();
  static {
    schemes.put(StandardScheme.class, new TPathsDumpStandardSchemeFactory());
    schemes.put(TupleScheme.class, new TPathsDumpTupleSchemeFactory());
  }

  private int rootId; // required
  private Map<Integer,TPathEntry> nodeMap; // required

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements org.apache.thrift.TFieldIdEnum {
    ROOT_ID((short)1, "rootId"),
    NODE_MAP((short)2, "nodeMap");

    private static final Map<String, _Fields> byName = new HashMap<String, _Fields>();

    static {
      for (_Fields field : EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        case 1: // ROOT_ID
          return ROOT_ID;
        case 2: // NODE_MAP
          return NODE_MAP;
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    public static _Fields findByName(String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final String _fieldName;

    _Fields(short thriftId, String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public String getFieldName() {
      return _fieldName;
    }
  }

  // isset id assignments
  private static final int __ROOTID_ISSET_ID = 0;
  private byte __isset_bitfield = 0;
  public static final Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> metaDataMap;
  static {
    Map<_Fields, org.apache.thrift.meta_data.FieldMetaData> tmpMap = new EnumMap<_Fields, org.apache.thrift.meta_data.FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.ROOT_ID, new org.apache.thrift.meta_data.FieldMetaData("rootId", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32)));
    tmpMap.put(_Fields.NODE_MAP, new org.apache.thrift.meta_data.FieldMetaData("nodeMap", org.apache.thrift.TFieldRequirementType.REQUIRED, 
        new org.apache.thrift.meta_data.MapMetaData(org.apache.thrift.protocol.TType.MAP, 
            new org.apache.thrift.meta_data.FieldValueMetaData(org.apache.thrift.protocol.TType.I32), 
            new org.apache.thrift.meta_data.StructMetaData(org.apache.thrift.protocol.TType.STRUCT, TPathEntry.class))));
    metaDataMap = Collections.unmodifiableMap(tmpMap);
    org.apache.thrift.meta_data.FieldMetaData.addStructMetaDataMap(TPathsDump.class, metaDataMap);
  }

  public TPathsDump() {
  }

  public TPathsDump(
    int rootId,
    Map<Integer,TPathEntry> nodeMap)
  {
    this();
    this.rootId = rootId;
    setRootIdIsSet(true);
    this.nodeMap = nodeMap;
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public TPathsDump(TPathsDump other) {
    __isset_bitfield = other.__isset_bitfield;
    this.rootId = other.rootId;
    if (other.isSetNodeMap()) {
      Map<Integer,TPathEntry> __this__nodeMap = new HashMap<Integer,TPathEntry>();
      for (Map.Entry<Integer, TPathEntry> other_element : other.nodeMap.entrySet()) {

        Integer other_element_key = other_element.getKey();
        TPathEntry other_element_value = other_element.getValue();

        Integer __this__nodeMap_copy_key = other_element_key;

        TPathEntry __this__nodeMap_copy_value = new TPathEntry(other_element_value);

        __this__nodeMap.put(__this__nodeMap_copy_key, __this__nodeMap_copy_value);
      }
      this.nodeMap = __this__nodeMap;
    }
  }

  public TPathsDump deepCopy() {
    return new TPathsDump(this);
  }

  @Override
  public void clear() {
    setRootIdIsSet(false);
    this.rootId = 0;
    this.nodeMap = null;
  }

  public int getRootId() {
    return this.rootId;
  }

  public void setRootId(int rootId) {
    this.rootId = rootId;
    setRootIdIsSet(true);
  }

  public void unsetRootId() {
    __isset_bitfield = EncodingUtils.clearBit(__isset_bitfield, __ROOTID_ISSET_ID);
  }

  /** Returns true if field rootId is set (has been assigned a value) and false otherwise */
  public boolean isSetRootId() {
    return EncodingUtils.testBit(__isset_bitfield, __ROOTID_ISSET_ID);
  }

  public void setRootIdIsSet(boolean value) {
    __isset_bitfield = EncodingUtils.setBit(__isset_bitfield, __ROOTID_ISSET_ID, value);
  }

  public int getNodeMapSize() {
    return (this.nodeMap == null) ? 0 : this.nodeMap.size();
  }

  public void putToNodeMap(int key, TPathEntry val) {
    if (this.nodeMap == null) {
      this.nodeMap = new HashMap<Integer,TPathEntry>();
    }
    this.nodeMap.put(key, val);
  }

  public Map<Integer,TPathEntry> getNodeMap() {
    return this.nodeMap;
  }

  public void setNodeMap(Map<Integer,TPathEntry> nodeMap) {
    this.nodeMap = nodeMap;
  }

  public void unsetNodeMap() {
    this.nodeMap = null;
  }

  /** Returns true if field nodeMap is set (has been assigned a value) and false otherwise */
  public boolean isSetNodeMap() {
    return this.nodeMap != null;
  }

  public void setNodeMapIsSet(boolean value) {
    if (!value) {
      this.nodeMap = null;
    }
  }

  public void setFieldValue(_Fields field, Object value) {
    switch (field) {
    case ROOT_ID:
      if (value == null) {
        unsetRootId();
      } else {
        setRootId((Integer)value);
      }
      break;

    case NODE_MAP:
      if (value == null) {
        unsetNodeMap();
      } else {
        setNodeMap((Map<Integer,TPathEntry>)value);
      }
      break;

    }
  }

  public Object getFieldValue(_Fields field) {
    switch (field) {
    case ROOT_ID:
      return Integer.valueOf(getRootId());

    case NODE_MAP:
      return getNodeMap();

    }
    throw new IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been assigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new IllegalArgumentException();
    }

    switch (field) {
    case ROOT_ID:
      return isSetRootId();
    case NODE_MAP:
      return isSetNodeMap();
    }
    throw new IllegalStateException();
  }

  @Override
  public boolean equals(Object that) {
    if (that == null)
      return false;
    if (that instanceof TPathsDump)
      return this.equals((TPathsDump)that);
    return false;
  }

  public boolean equals(TPathsDump that) {
    if (that == null)
      return false;

    boolean this_present_rootId = true;
    boolean that_present_rootId = true;
    if (this_present_rootId || that_present_rootId) {
      if (!(this_present_rootId && that_present_rootId))
        return false;
      if (this.rootId != that.rootId)
        return false;
    }

    boolean this_present_nodeMap = true && this.isSetNodeMap();
    boolean that_present_nodeMap = true && that.isSetNodeMap();
    if (this_present_nodeMap || that_present_nodeMap) {
      if (!(this_present_nodeMap && that_present_nodeMap))
        return false;
      if (!this.nodeMap.equals(that.nodeMap))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    HashCodeBuilder builder = new HashCodeBuilder();

    boolean present_rootId = true;
    builder.append(present_rootId);
    if (present_rootId)
      builder.append(rootId);

    boolean present_nodeMap = true && (isSetNodeMap());
    builder.append(present_nodeMap);
    if (present_nodeMap)
      builder.append(nodeMap);

    return builder.toHashCode();
  }

  public int compareTo(TPathsDump other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }

    int lastComparison = 0;
    TPathsDump typedOther = (TPathsDump)other;

    lastComparison = Boolean.valueOf(isSetRootId()).compareTo(typedOther.isSetRootId());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetRootId()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.rootId, typedOther.rootId);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    lastComparison = Boolean.valueOf(isSetNodeMap()).compareTo(typedOther.isSetNodeMap());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetNodeMap()) {
      lastComparison = org.apache.thrift.TBaseHelper.compareTo(this.nodeMap, typedOther.nodeMap);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }

  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(org.apache.thrift.protocol.TProtocol iprot) throws org.apache.thrift.TException {
    schemes.get(iprot.getScheme()).getScheme().read(iprot, this);
  }

  public void write(org.apache.thrift.protocol.TProtocol oprot) throws org.apache.thrift.TException {
    schemes.get(oprot.getScheme()).getScheme().write(oprot, this);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("TPathsDump(");
    boolean first = true;

    sb.append("rootId:");
    sb.append(this.rootId);
    first = false;
    if (!first) sb.append(", ");
    sb.append("nodeMap:");
    if (this.nodeMap == null) {
      sb.append("null");
    } else {
      sb.append(this.nodeMap);
    }
    first = false;
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws org.apache.thrift.TException {
    // check for required fields
    if (!isSetRootId()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'rootId' is unset! Struct:" + toString());
    }

    if (!isSetNodeMap()) {
      throw new org.apache.thrift.protocol.TProtocolException("Required field 'nodeMap' is unset! Struct:" + toString());
    }

    // check for sub-struct validity
  }

  private void writeObject(java.io.ObjectOutputStream out) throws java.io.IOException {
    try {
      write(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(out)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private void readObject(java.io.ObjectInputStream in) throws java.io.IOException, ClassNotFoundException {
    try {
      // it doesn't seem like you should have to do this, but java serialization is wacky, and doesn't call the default constructor.
      __isset_bitfield = 0;
      read(new org.apache.thrift.protocol.TCompactProtocol(new org.apache.thrift.transport.TIOStreamTransport(in)));
    } catch (org.apache.thrift.TException te) {
      throw new java.io.IOException(te);
    }
  }

  private static class TPathsDumpStandardSchemeFactory implements SchemeFactory {
    public TPathsDumpStandardScheme getScheme() {
      return new TPathsDumpStandardScheme();
    }
  }

  private static class TPathsDumpStandardScheme extends StandardScheme<TPathsDump> {

    public void read(org.apache.thrift.protocol.TProtocol iprot, TPathsDump struct) throws org.apache.thrift.TException {
      org.apache.thrift.protocol.TField schemeField;
      iprot.readStructBegin();
      while (true)
      {
        schemeField = iprot.readFieldBegin();
        if (schemeField.type == org.apache.thrift.protocol.TType.STOP) { 
          break;
        }
        switch (schemeField.id) {
          case 1: // ROOT_ID
            if (schemeField.type == org.apache.thrift.protocol.TType.I32) {
              struct.rootId = iprot.readI32();
              struct.setRootIdIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          case 2: // NODE_MAP
            if (schemeField.type == org.apache.thrift.protocol.TType.MAP) {
              {
                org.apache.thrift.protocol.TMap _map48 = iprot.readMapBegin();
                struct.nodeMap = new HashMap<Integer,TPathEntry>(2*_map48.size);
                for (int _i49 = 0; _i49 < _map48.size; ++_i49)
                {
                  int _key50; // required
                  TPathEntry _val51; // required
                  _key50 = iprot.readI32();
                  _val51 = new TPathEntry();
                  _val51.read(iprot);
                  struct.nodeMap.put(_key50, _val51);
                }
                iprot.readMapEnd();
              }
              struct.setNodeMapIsSet(true);
            } else { 
              org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
            }
            break;
          default:
            org.apache.thrift.protocol.TProtocolUtil.skip(iprot, schemeField.type);
        }
        iprot.readFieldEnd();
      }
      iprot.readStructEnd();
      struct.validate();
    }

    public void write(org.apache.thrift.protocol.TProtocol oprot, TPathsDump struct) throws org.apache.thrift.TException {
      struct.validate();

      oprot.writeStructBegin(STRUCT_DESC);
      oprot.writeFieldBegin(ROOT_ID_FIELD_DESC);
      oprot.writeI32(struct.rootId);
      oprot.writeFieldEnd();
      if (struct.nodeMap != null) {
        oprot.writeFieldBegin(NODE_MAP_FIELD_DESC);
        {
          oprot.writeMapBegin(new org.apache.thrift.protocol.TMap(org.apache.thrift.protocol.TType.I32, org.apache.thrift.protocol.TType.STRUCT, struct.nodeMap.size()));
          for (Map.Entry<Integer, TPathEntry> _iter52 : struct.nodeMap.entrySet())
          {
            oprot.writeI32(_iter52.getKey());
            _iter52.getValue().write(oprot);
          }
          oprot.writeMapEnd();
        }
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }

  }

  private static class TPathsDumpTupleSchemeFactory implements SchemeFactory {
    public TPathsDumpTupleScheme getScheme() {
      return new TPathsDumpTupleScheme();
    }
  }

  private static class TPathsDumpTupleScheme extends TupleScheme<TPathsDump> {

    @Override
    public void write(org.apache.thrift.protocol.TProtocol prot, TPathsDump struct) throws org.apache.thrift.TException {
      TTupleProtocol oprot = (TTupleProtocol) prot;
      oprot.writeI32(struct.rootId);
      {
        oprot.writeI32(struct.nodeMap.size());
        for (Map.Entry<Integer, TPathEntry> _iter53 : struct.nodeMap.entrySet())
        {
          oprot.writeI32(_iter53.getKey());
          _iter53.getValue().write(oprot);
        }
      }
    }

    @Override
    public void read(org.apache.thrift.protocol.TProtocol prot, TPathsDump struct) throws org.apache.thrift.TException {
      TTupleProtocol iprot = (TTupleProtocol) prot;
      struct.rootId = iprot.readI32();
      struct.setRootIdIsSet(true);
      {
        org.apache.thrift.protocol.TMap _map54 = new org.apache.thrift.protocol.TMap(org.apache.thrift.protocol.TType.I32, org.apache.thrift.protocol.TType.STRUCT, iprot.readI32());
        struct.nodeMap = new HashMap<Integer,TPathEntry>(2*_map54.size);
        for (int _i55 = 0; _i55 < _map54.size; ++_i55)
        {
          int _key56; // required
          TPathEntry _val57; // required
          _key56 = iprot.readI32();
          _val57 = new TPathEntry();
          _val57.read(iprot);
          struct.nodeMap.put(_key56, _val57);
        }
      }
      struct.setNodeMapIsSet(true);
    }
  }

}

