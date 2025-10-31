import mongoose  from "mongoose";
const taskSchema = new mongoose.Schema({

    title: {type: String, required: true},
    description: {type: String, required: true},
    done: {type: Boolean, default: false},
    date: {type: Date, default: Date.now},},
    {timestamps: true}
)

export default mongoose.model('Task', taskSchema);