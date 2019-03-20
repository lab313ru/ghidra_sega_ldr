package sega;

import ghidra.program.model.address.Address;

public class VectorFunc {
	private Address address;
	private String name;
	
	public VectorFunc(Address address, String name) {
		this.address = address;
		this.name = name;
	}
	
	public Address getAddress() {
		return address;
	}
	
	public String getName() {
		return name;
	}
}
