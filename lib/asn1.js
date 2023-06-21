module.exports.Asn1Obj = class Asn1Obj {
  constructor() {
    this.tag_ = null;
    this.value_ = null; // For primitive
    this.children_ = []; // For constructed
  }
  // Static functions
  // array: Uint8Array
  static load(array) {
    var root = new Asn1Obj();
    root.#loadInConstructed(root, array, 0);
    return root.getChildren()[0];
  }
  static create(tag) {
    var obj = new Asn1Obj();
    obj.setTag(tag);
    return obj;
  }
  // Public functions
  setTag(tag) {
    this.tag_ = tag;
    return this;
  }
  setValue(value) {
    this.value_ = value;
    return this;
  }
  addChild(asn1Obj) {
    this.children_.push(asn1Obj);
    return this;
  }
  getPath(path) {
    const node = this;
    for (const tag in path) {
      node = node?.children_.find((child) => child.tag === name);
    }
    return node;
  }
  getTag() {
    return this.tag_;
  }
  getValue() {
    return this.value_;
  }
  getChildren() {
    return this.children_;
  }
  getChild(index) {
    return this.getChildren()[index];
  }
  /*jslint bitwise: true */
  isPrimitive() {
    return (this.tag_ & 0x20) === 0; // If 6th bit === 1, it's constructed.
  }
  getValueAsObjectIdentifier() {
    if (!this.value_) {
      return null;
    }

    var result = [];
    if (this.value_[0] > 80) {
      result.push(2);
      result.push(this.value_[0] - 80);
    } else if (this.value_[0] > 40) {
      result.push(1);
      result.push(this.value_[0] - 40);
    } else {
      result.push(0);
      result.push(this.value_[0]);
    }

    var stack = [];
    for (var i = 1; i < this.value_.length; i++) {
      stack.push(this.value_[i] & 0x7f);
      if ((this.value_[i] & 0x80) === 0) {
        var value = 0;
        for (var j = 0; j < stack.length; j++) {
          value = value << (j * 7);
          value += stack[j];
        }
        result.push(value);
        stack = [];
      }
    }

    return result.join('.');
  }
  createArrayBuffer() {
    var root = {
      children: [],
    };
    this.#createBufferTree(root);
    return this.#traverseAndCreate(root.children[0]);
  }

  #loadInConstructed(parent, array, pos) {
    if (array.length <= pos) {
      return;
    }
    var tag = array[pos];
    var obj = new Asn1Obj();
    obj.setTag(tag);
    var valueAndNext = this.#loadValueAndNext(array, pos + 1);
    var value = valueAndNext.value;
    var next = valueAndNext.next;
    if (obj.isPrimitive()) {
      obj.setValue(value);
      parent.addChild(obj);
    } else {
      parent.addChild(obj);
      this.#loadInConstructed(obj, value, 0);
    }
    this.#loadInConstructed(parent, array, next);
  }

  // pos is started at length (except tag)
  #loadValueAndNext(array, pos) {
    var view = new DataView(new Uint8Array(array).buffer);
    var value = null;
    var length1 = array[pos];
    var next = null;
    if (length1 <= 0x7f) {
      value = array.subarray(pos + 1, pos + 1 + length1);
      next = pos + 1 + length1;
    } else if (length1 === 0x81) {
      value = array.subarray(pos + 2, pos + 2 + array[pos + 1]);
      next = pos + 2 + array[pos + 1];
    } else if (length1 === 0x82) {
      value = array.subarray(pos + 3, pos + 3 + view.getUint16(pos + 1, false));
      next = pos + 3 + view.getUint16(pos + 1, false);
    } else if (length1 === 0x80) {
      for (var i = pos + 1; i < array.length - 1; i++) {
        if (view.getInt16(i, false) === 0) {
          value = array.subarray(pos + 1, i);
          next = i + 2;
          break;
        }
      }
    }
    return {
      value: value,
      next: next,
    };
  }

  #traverseAndCreate(node) {
    if (node.primitive) {
      return node.buffer;
    } else {
      var length = 0;
      var buffers = [];
      var i;
      for (i = 0; i < node.children.length; i++) {
        var buffer = this.#traverseAndCreate(node.children[i]);
        buffers.push(buffer);
        length += buffer.byteLength;
      }
      var concatedBuffer = new ArrayBuffer(length);
      var concatedArray = new Uint8Array(concatedBuffer);
      var pos = 0;
      for (i = 0; i < buffers.length; i++) {
        var array = new Uint8Array(buffers[i]);
        for (var j = 0; j < array.length; j++) {
          concatedArray[pos + j] = array[j];
        }
        pos += array.length;
      }
      return this.#createObjectArrayBuffer(node.tag, concatedArray);
    }
  }

  #createBufferTree(parent) {
    var obj;
    if (this.isPrimitive()) {
      var buffer = this.#createObjectArrayBuffer(this.tag_, this.value_);
      obj = {
        primitive: true,
        tag: this.getTag(),
        buffer: buffer,
        length: buffer.byteLength,
        children: [],
      };
      parent.children.push(obj);
    } else {
      obj = {
        primitive: false,
        tag: this.getTag(),
        children: [],
      };
      parent.children.push(obj);
      for (var i = 0; i < this.getChildren().length; i++) {
        this.getChildren()[i].#createBufferTree(obj);
      }
    }
  }

  #createObjectArrayBuffer(tag, value) {
    var valueLength = value.length;
    var length;
    var buffer;
    if (valueLength <= 127) {
      length = new Uint8Array([valueLength]);
      buffer = new ArrayBuffer(1 + 1 + valueLength);
    } else if (valueLength <= 255) {
      length = new Uint8Array([0x81, valueLength]);
      buffer = new ArrayBuffer(1 + 2 + valueLength);
    } else if (valueLength <= 65535) {
      length = new Uint8Array([0x82, 0, 0]);
      var view = new DataView(length.buffer);
      view.setUint16(1, valueLength, false);
      buffer = new ArrayBuffer(1 + 3 + valueLength);
    } else {
      length = new Uint8Array([0x80]);
      buffer = new ArrayBuffer(1 + valueLength + 2);
    }

    var i;
    var array = new Uint8Array(buffer);
    array[0] = tag;
    for (i = 0; i < length.length; i++) {
      array[i + 1] = length[i];
    }
    for (i = 0; i < value.length; i++) {
      array[1 + length.length + i] = value[i];
    }
    return buffer;
  }
};
