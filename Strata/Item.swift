//
//  Item.swift
//  Strata
//
//  Created by Norbert Bonnici on 02/06/2026.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
